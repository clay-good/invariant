// CNC tending cycle state machine (Step 67).
//
// Models the complete load/unload cycle from CNC cell specification Section 5.
// The coordinator manages:
// - Cycle state transitions (IDLE → PICK_APPROACH → ... → CYCLE_COMPLETE)
// - Conditional zone overrides (haas_spindle_zone active/inactive per phase)
// - I/O signal tracking (HAAS_READY, HAAS_CYCLE_COMPLETE, VISE_CLAMP, etc.)
// - Gripper state
//
// This is a pure state machine — no I/O, no hardware access. The caller
// (CLI `tend` command, Isaac Lab bridge, or real edge PC controller) maps
// external signals to `HaasSignal` and calls `advance()`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Cycle states
// ---------------------------------------------------------------------------

/// States of the CNC tending cycle from Section 5.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CycleState {
    /// Robot at home position, waiting for start signal.
    Idle,
    /// Moving to above raw stock pallet (W0→W1).
    PickApproach,
    /// Lowering into pallet to grip billet (W1→W2).
    PickBillet,
    /// Lifting billet clear of pallet (W2→W3).
    PickLift,
    /// Checking if Haas is ready (idle + door open).
    CheckHaasReady,
    /// Waiting for Haas to finish current cycle.
    WaitHaasReady,
    /// Moving to in front of Haas door opening (W3→W4).
    DoorApproach,
    /// Moving to above vise inside enclosure (W4→W5).
    ViseApproach,
    /// Lowering billet into vise jaws (W5→W6).
    VisePlace,
    /// Commanding vise to clamp.
    ViseClamp,
    /// Retracting from enclosure after loading (W6→W7).
    ViseRetreat,
    /// Signaling Haas to start machining cycle.
    SignalHaasStart,
    /// Waiting for machining to complete (~40 min per workpiece).
    WaitMachining,
    /// Commanding vise to unclamp after machining.
    ViseUnclamp,
    /// Gripping finished part from vise (W8).
    PickFinished,
    /// Moving to above finished parts pallet (W7→W9).
    FinishedApproach,
    /// Placing finished part on pallet (W9→W10).
    PlaceDone,
    /// Checking if raw stock remains.
    CheckStock,
    /// All stock processed; cycle complete.
    CycleComplete,
}

// ---------------------------------------------------------------------------
// I/O signals
// ---------------------------------------------------------------------------

/// External signals that can cause state transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HaasSignal {
    /// Haas is idle, door open, safe to enter.
    HaasReady,
    /// Haas is still busy (cutting).
    HaasBusy,
    /// Machining complete, door opening.
    HaasCycleComplete,
}

/// Commands to actuators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActuatorCommand {
    GripperClose,
    GripperOpen,
    ViseClamp,
    ViseUnclamp,
    HaasCycleStart,
}

// ---------------------------------------------------------------------------
// Transition result
// ---------------------------------------------------------------------------

/// The result of a state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionResult {
    /// Previous state.
    pub from: CycleState,
    /// New state.
    pub to: CycleState,
    /// Actuator commands to issue (may be empty).
    pub commands: Vec<ActuatorCommand>,
    /// Whether the spindle exclusion zone state changed.
    pub zone_changed: bool,
}

// ---------------------------------------------------------------------------
// Cycle coordinator
// ---------------------------------------------------------------------------

/// The name of the conditional exclusion zone managed by this coordinator.
const SPINDLE_ZONE_NAME: &str = "haas_spindle_zone";

/// CNC tending cycle coordinator.
///
/// Pure state machine. Call `advance()` to move to the next state. The
/// coordinator determines whether the spindle exclusion zone should be
/// active or inactive at each point in the cycle.
#[derive(Debug, Clone)]
pub struct CycleCoordinator {
    state: CycleState,
    /// Whether the spindle exclusion zone is currently active.
    spindle_zone_active: bool,
    /// Number of billets remaining in the stock pallet.
    billets_remaining: u32,
    /// Total parts machined in this session.
    parts_completed: u32,
}

impl CycleCoordinator {
    /// Create a new coordinator with the robot in IDLE state.
    ///
    /// `billets` is the number of raw billets loaded on the stock pallet.
    /// The spindle exclusion zone starts ACTIVE (safe default).
    pub fn new(billets: u32) -> Self {
        Self {
            state: CycleState::Idle,
            spindle_zone_active: true,
            billets_remaining: billets,
            parts_completed: 0,
        }
    }

    /// Current cycle state.
    pub fn state(&self) -> CycleState {
        self.state
    }

    /// Whether the spindle exclusion zone is currently active.
    pub fn spindle_zone_active(&self) -> bool {
        self.spindle_zone_active
    }

    /// Number of billets remaining.
    pub fn billets_remaining(&self) -> u32 {
        self.billets_remaining
    }

    /// Total parts completed.
    pub fn parts_completed(&self) -> u32 {
        self.parts_completed
    }

    /// Generate the `zone_overrides` map for the current cycle state.
    ///
    /// This is the map that should be set on `Command.zone_overrides` for
    /// every command issued in the current state. The edge PC controller
    /// calls this before constructing each command.
    pub fn zone_overrides(&self) -> HashMap<String, bool> {
        let mut overrides = HashMap::new();
        overrides.insert(SPINDLE_ZONE_NAME.to_string(), self.spindle_zone_active);
        overrides
    }

    /// Advance to the next state.
    ///
    /// `haas_signal` is required for states that wait on Haas I/O
    /// (`CheckHaasReady`, `WaitHaasReady`, `WaitMachining`). For all other
    /// states, pass `None`.
    ///
    /// Returns `Ok(TransitionResult)` on success, or `Err(message)` if
    /// the transition is invalid (wrong signal, already complete, etc.).
    pub fn advance(&mut self, haas_signal: Option<HaasSignal>) -> Result<TransitionResult, String> {
        let from = self.state;

        let (next, commands, zone_changed) = match self.state {
            CycleState::Idle => {
                if self.billets_remaining == 0 {
                    return Err("no billets remaining; cannot start cycle".into());
                }
                (CycleState::PickApproach, vec![], false)
            }

            CycleState::PickApproach => (CycleState::PickBillet, vec![], false),

            CycleState::PickBillet => {
                self.billets_remaining = self.billets_remaining.saturating_sub(1);
                (
                    CycleState::PickLift,
                    vec![ActuatorCommand::GripperClose],
                    false,
                )
            }

            CycleState::PickLift => (CycleState::CheckHaasReady, vec![], false),

            CycleState::CheckHaasReady => match haas_signal {
                Some(HaasSignal::HaasReady) => (CycleState::DoorApproach, vec![], false),
                Some(HaasSignal::HaasBusy) => (CycleState::WaitHaasReady, vec![], false),
                _ => return Err("CheckHaasReady requires HaasReady or HaasBusy signal".into()),
            },

            CycleState::WaitHaasReady => match haas_signal {
                Some(HaasSignal::HaasReady) => (CycleState::DoorApproach, vec![], false),
                Some(HaasSignal::HaasBusy) => (CycleState::WaitHaasReady, vec![], false),
                _ => return Err("WaitHaasReady requires HaasReady or HaasBusy signal".into()),
            },

            CycleState::DoorApproach => {
                // Disable spindle exclusion zone so robot can enter enclosure.
                self.spindle_zone_active = false;
                (CycleState::ViseApproach, vec![], true)
            }

            CycleState::ViseApproach => (CycleState::VisePlace, vec![], false),

            CycleState::VisePlace => (
                CycleState::ViseClamp,
                vec![ActuatorCommand::GripperOpen, ActuatorCommand::ViseClamp],
                false,
            ),

            CycleState::ViseClamp => (CycleState::ViseRetreat, vec![], false),

            CycleState::ViseRetreat => {
                // Re-enable spindle exclusion zone after exiting enclosure.
                self.spindle_zone_active = true;
                (CycleState::SignalHaasStart, vec![], true)
            }

            CycleState::SignalHaasStart => (
                CycleState::WaitMachining,
                vec![ActuatorCommand::HaasCycleStart],
                false,
            ),

            CycleState::WaitMachining => match haas_signal {
                Some(HaasSignal::HaasCycleComplete) => {
                    // Disable spindle exclusion zone for unloading.
                    self.spindle_zone_active = false;
                    (CycleState::ViseUnclamp, vec![], true)
                }
                Some(HaasSignal::HaasBusy) => (CycleState::WaitMachining, vec![], false),
                _ => {
                    return Err(
                        "WaitMachining requires HaasCycleComplete or HaasBusy signal".into(),
                    )
                }
            },

            CycleState::ViseUnclamp => (
                CycleState::PickFinished,
                vec![ActuatorCommand::ViseUnclamp, ActuatorCommand::GripperClose],
                false,
            ),

            CycleState::PickFinished => {
                // Re-enable spindle exclusion zone after picking finished part.
                self.spindle_zone_active = true;
                (CycleState::FinishedApproach, vec![], true)
            }

            CycleState::FinishedApproach => (CycleState::PlaceDone, vec![], false),

            CycleState::PlaceDone => {
                self.parts_completed += 1;
                (
                    CycleState::CheckStock,
                    vec![ActuatorCommand::GripperOpen],
                    false,
                )
            }

            CycleState::CheckStock => {
                if self.billets_remaining > 0 {
                    (CycleState::PickApproach, vec![], false)
                } else {
                    (CycleState::CycleComplete, vec![], false)
                }
            }

            CycleState::CycleComplete => {
                return Err("cycle already complete; reset to start a new cycle".into());
            }
        };

        self.state = next;

        Ok(TransitionResult {
            from,
            to: next,
            commands,
            zone_changed,
        })
    }

    /// Reset the coordinator for a new cycle.
    ///
    /// Can only be called from `CycleComplete` or `Idle`. Sets state back to
    /// `Idle` with the spindle exclusion zone active.
    pub fn reset(&mut self, billets: u32) -> Result<(), String> {
        match self.state {
            CycleState::CycleComplete | CycleState::Idle => {
                self.state = CycleState::Idle;
                self.spindle_zone_active = true;
                self.billets_remaining = billets;
                Ok(())
            }
            _ => Err(format!(
                "cannot reset from state {:?}; must be Idle or CycleComplete",
                self.state
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_coordinator_starts_idle_with_active_spindle_zone() {
        let coord = CycleCoordinator::new(10);
        assert_eq!(coord.state(), CycleState::Idle);
        assert!(coord.spindle_zone_active());
        assert_eq!(coord.billets_remaining(), 10);
        assert_eq!(coord.parts_completed(), 0);
    }

    #[test]
    fn zone_overrides_reflect_spindle_state() {
        let coord = CycleCoordinator::new(1);
        let overrides = coord.zone_overrides();
        assert_eq!(overrides.get(SPINDLE_ZONE_NAME), Some(&true));
    }

    #[test]
    fn full_single_billet_cycle() {
        let mut coord = CycleCoordinator::new(1);

        // IDLE → PICK_APPROACH
        let r = coord.advance(None).unwrap();
        assert_eq!(r.from, CycleState::Idle);
        assert_eq!(r.to, CycleState::PickApproach);
        assert!(!r.zone_changed);

        // PICK_APPROACH → PICK_BILLET
        coord.advance(None).unwrap();
        assert_eq!(coord.state(), CycleState::PickBillet);

        // PICK_BILLET → PICK_LIFT (gripper closes, billet count decremented)
        let r = coord.advance(None).unwrap();
        assert_eq!(r.to, CycleState::PickLift);
        assert!(r.commands.contains(&ActuatorCommand::GripperClose));
        assert_eq!(coord.billets_remaining(), 0);

        // PICK_LIFT → CHECK_HAAS_READY
        coord.advance(None).unwrap();
        assert_eq!(coord.state(), CycleState::CheckHaasReady);

        // CHECK_HAAS_READY + HaasReady → DOOR_APPROACH
        coord.advance(Some(HaasSignal::HaasReady)).unwrap();
        assert_eq!(coord.state(), CycleState::DoorApproach);

        // DOOR_APPROACH → VISE_APPROACH (spindle zone disabled)
        let r = coord.advance(None).unwrap();
        assert_eq!(r.to, CycleState::ViseApproach);
        assert!(r.zone_changed);
        assert!(!coord.spindle_zone_active());

        // VISE_APPROACH → VISE_PLACE
        coord.advance(None).unwrap();

        // VISE_PLACE → VISE_CLAMP (gripper opens, vise clamps)
        let r = coord.advance(None).unwrap();
        assert_eq!(r.to, CycleState::ViseClamp);
        assert!(r.commands.contains(&ActuatorCommand::GripperOpen));
        assert!(r.commands.contains(&ActuatorCommand::ViseClamp));

        // VISE_CLAMP → VISE_RETREAT
        coord.advance(None).unwrap();

        // VISE_RETREAT → SIGNAL_HAAS_START (spindle zone re-enabled)
        let r = coord.advance(None).unwrap();
        assert_eq!(r.to, CycleState::SignalHaasStart);
        assert!(r.zone_changed);
        assert!(coord.spindle_zone_active());

        // SIGNAL_HAAS_START → WAIT_MACHINING (sends HaasCycleStart)
        let r = coord.advance(None).unwrap();
        assert_eq!(r.to, CycleState::WaitMachining);
        assert!(r.commands.contains(&ActuatorCommand::HaasCycleStart));

        // WAIT_MACHINING + HaasCycleComplete → VISE_UNCLAMP (spindle zone disabled)
        let r = coord.advance(Some(HaasSignal::HaasCycleComplete)).unwrap();
        assert_eq!(r.to, CycleState::ViseUnclamp);
        assert!(r.zone_changed);
        assert!(!coord.spindle_zone_active());

        // VISE_UNCLAMP → PICK_FINISHED
        let r = coord.advance(None).unwrap();
        assert_eq!(r.to, CycleState::PickFinished);
        assert!(r.commands.contains(&ActuatorCommand::ViseUnclamp));
        assert!(r.commands.contains(&ActuatorCommand::GripperClose));

        // PICK_FINISHED → FINISHED_APPROACH (spindle zone re-enabled)
        let r = coord.advance(None).unwrap();
        assert_eq!(r.to, CycleState::FinishedApproach);
        assert!(r.zone_changed);
        assert!(coord.spindle_zone_active());

        // FINISHED_APPROACH → PLACE_DONE
        coord.advance(None).unwrap();

        // PLACE_DONE → CHECK_STOCK (parts completed incremented)
        let r = coord.advance(None).unwrap();
        assert_eq!(r.to, CycleState::CheckStock);
        assert!(r.commands.contains(&ActuatorCommand::GripperOpen));
        assert_eq!(coord.parts_completed(), 1);

        // CHECK_STOCK → CYCLE_COMPLETE (no billets left)
        coord.advance(None).unwrap();
        assert_eq!(coord.state(), CycleState::CycleComplete);
    }

    #[test]
    fn haas_busy_causes_wait() {
        let mut coord = CycleCoordinator::new(1);
        // Advance to CHECK_HAAS_READY.
        coord.advance(None).unwrap(); // → PickApproach
        coord.advance(None).unwrap(); // → PickBillet
        coord.advance(None).unwrap(); // → PickLift
        coord.advance(None).unwrap(); // → CheckHaasReady

        // Haas busy → WAIT.
        coord.advance(Some(HaasSignal::HaasBusy)).unwrap();
        assert_eq!(coord.state(), CycleState::WaitHaasReady);

        // Still busy → stay in WAIT.
        coord.advance(Some(HaasSignal::HaasBusy)).unwrap();
        assert_eq!(coord.state(), CycleState::WaitHaasReady);

        // Ready → DOOR_APPROACH.
        coord.advance(Some(HaasSignal::HaasReady)).unwrap();
        assert_eq!(coord.state(), CycleState::DoorApproach);
    }

    #[test]
    fn wait_machining_stays_while_busy() {
        let mut coord = CycleCoordinator::new(1);
        // Fast-forward to WAIT_MACHINING.
        coord.advance(None).unwrap(); // → PickApproach
        coord.advance(None).unwrap(); // → PickBillet
        coord.advance(None).unwrap(); // → PickLift
        coord.advance(None).unwrap(); // → CheckHaasReady
        coord.advance(Some(HaasSignal::HaasReady)).unwrap(); // → DoorApproach
        coord.advance(None).unwrap(); // → ViseApproach
        coord.advance(None).unwrap(); // → VisePlace
        coord.advance(None).unwrap(); // → ViseClamp
        coord.advance(None).unwrap(); // → ViseRetreat
        coord.advance(None).unwrap(); // → SignalHaasStart
        coord.advance(None).unwrap(); // → WaitMachining

        // Busy → stay in WAIT_MACHINING.
        coord.advance(Some(HaasSignal::HaasBusy)).unwrap();
        assert_eq!(coord.state(), CycleState::WaitMachining);
        assert!(coord.spindle_zone_active()); // still active during machining
    }

    #[test]
    fn multi_billet_cycle_loops() {
        let mut coord = CycleCoordinator::new(2);

        // Complete first billet (fast-forward through all states).
        for signal in full_cycle_signals() {
            coord.advance(signal).unwrap();
        }
        assert_eq!(coord.state(), CycleState::CheckStock);
        assert_eq!(coord.billets_remaining(), 1);
        assert_eq!(coord.parts_completed(), 1);

        // CHECK_STOCK → PICK_APPROACH (more stock).
        coord.advance(None).unwrap();
        assert_eq!(coord.state(), CycleState::PickApproach);
    }

    #[test]
    fn cannot_start_with_zero_billets() {
        let mut coord = CycleCoordinator::new(0);
        let result = coord.advance(None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no billets"));
    }

    #[test]
    fn cannot_advance_past_cycle_complete() {
        let mut coord = CycleCoordinator::new(1);
        // Complete the full cycle.
        for signal in full_cycle_signals() {
            coord.advance(signal).unwrap();
        }
        coord.advance(None).unwrap(); // CHECK_STOCK → CYCLE_COMPLETE

        let result = coord.advance(None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already complete"));
    }

    #[test]
    fn reset_from_cycle_complete() {
        let mut coord = CycleCoordinator::new(1);
        for signal in full_cycle_signals() {
            coord.advance(signal).unwrap();
        }
        coord.advance(None).unwrap(); // → CYCLE_COMPLETE

        coord.reset(5).unwrap();
        assert_eq!(coord.state(), CycleState::Idle);
        assert!(coord.spindle_zone_active());
        assert_eq!(coord.billets_remaining(), 5);
    }

    #[test]
    fn cannot_reset_mid_cycle() {
        let mut coord = CycleCoordinator::new(1);
        coord.advance(None).unwrap(); // → PickApproach
        let result = coord.reset(5);
        assert!(result.is_err());
    }

    #[test]
    fn spindle_zone_disabled_during_load_and_unload() {
        let mut coord = CycleCoordinator::new(1);

        // Advance to DOOR_APPROACH.
        coord.advance(None).unwrap(); // → PickApproach
        coord.advance(None).unwrap(); // → PickBillet
        coord.advance(None).unwrap(); // → PickLift
        coord.advance(None).unwrap(); // → CheckHaasReady
        coord.advance(Some(HaasSignal::HaasReady)).unwrap(); // → DoorApproach
        assert!(coord.spindle_zone_active()); // still active before entry

        // DOOR_APPROACH → ViseApproach: zone disabled.
        coord.advance(None).unwrap();
        assert!(!coord.spindle_zone_active());
        let overrides = coord.zone_overrides();
        assert_eq!(overrides.get(SPINDLE_ZONE_NAME), Some(&false));

        // Continue through loading...
        coord.advance(None).unwrap(); // → VisePlace
        coord.advance(None).unwrap(); // → ViseClamp
        coord.advance(None).unwrap(); // → ViseRetreat
        assert!(!coord.spindle_zone_active()); // still disabled during retreat

        // VISE_RETREAT → SignalHaasStart: zone re-enabled.
        coord.advance(None).unwrap();
        assert!(coord.spindle_zone_active());
    }

    #[test]
    fn check_haas_ready_requires_signal() {
        let mut coord = CycleCoordinator::new(1);
        coord.advance(None).unwrap(); // → PickApproach
        coord.advance(None).unwrap(); // → PickBillet
        coord.advance(None).unwrap(); // → PickLift
        coord.advance(None).unwrap(); // → CheckHaasReady

        let result = coord.advance(None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("requires"));
    }

    #[test]
    fn serde_round_trip_cycle_state() {
        let state = CycleState::WaitMachining;
        let json = serde_json::to_string(&state).unwrap();
        let back: CycleState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }

    /// Helper: signals needed to advance one full billet from IDLE to CHECK_STOCK.
    fn full_cycle_signals() -> Vec<Option<HaasSignal>> {
        vec![
            None,                                // IDLE → PickApproach
            None,                                // → PickBillet
            None,                                // → PickLift
            None,                                // → CheckHaasReady
            Some(HaasSignal::HaasReady),         // → DoorApproach
            None,                                // → ViseApproach
            None,                                // → VisePlace
            None,                                // → ViseClamp
            None,                                // → ViseRetreat
            None,                                // → SignalHaasStart
            None,                                // → WaitMachining
            Some(HaasSignal::HaasCycleComplete), // → ViseUnclamp
            None,                                // → PickFinished
            None,                                // → FinishedApproach
            None,                                // → PlaceDone
            None,                                // → CheckStock
        ]
    }
}
