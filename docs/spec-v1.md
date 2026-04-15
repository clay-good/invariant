# Invariant v1 -- Simulation Campaign & Expanded Safety Specification

## Purpose

This document specifies the expanded robot platform matrix, comprehensive test coverage, sensor integration requirements, and the 10M+ Isaac Sim simulation campaign that constitutes statistical proof of safety for Invariant.

It builds on the core build specification (`docs/spec.md`) and focuses specifically on:
1. Every robot platform Invariant must protect
2. Every failure mode Invariant must catch
3. Every sensor signal Invariant must validate
4. The exact simulation campaign that proves it works
5. How to execute that campaign on RunPod with NVIDIA Isaac Lab

---

## 1. Robot Platform Matrix

Invariant is robot-agnostic -- it validates commands against a declarative profile, not specific hardware. But the proof must cover the robots that matter. Every platform below gets a profile, a test suite, and simulation hours.

### 1.1 Humanoid Robots (Primary Target)

These are the platforms where LLM/AI cognitive control is actively being deployed. Humanoids are the highest-risk, highest-value target for Invariant.

| Robot | Manufacturer | DOF | Key Specs | Why It Matters |
|-------|-------------|-----|-----------|----------------|
| **GR-1** | Fourier Intelligence / NVIDIA GR00T | 40 | 1.64m, 55kg, 50kg payload capacity, 5km/h walk | NVIDIA's reference humanoid for GR00T foundation model |
| **Optimus Gen 2** | Tesla | 28 body + 22 hands = 50 | 1.73m, 57kg, 11 DOF hands, 4.5km/h walk | Largest deployment target (factory/home) |
| **Figure 02** | Figure AI | 42+ | 1.67m, ~60kg, dexterous manipulation | OpenAI partnership, LLM-first cognitive architecture |
| **Atlas (Electric)** | Boston Dynamics | ~28 | 1.5m, 89kg, most dynamic humanoid | Gold standard for dynamic stability |
| **Digit** | Agility Robotics | 16 | 1.75m, 65kg, warehouse logistics focus | Amazon deployment, constrained DOF |
| **H1 / G1** | Unitree | 19 / 23 | H1: 1.8m, 47kg; G1: 1.32m, 35kg | Lowest cost, highest volume, Isaac Lab native |
| **Phoenix** | Sanctuary AI | 20+ | 1.7m, general-purpose hands, Carbon AI | Focus on dexterous manipulation |
| **NEO** | 1X Technologies | ~30 | 1.65m, 30kg, compliant actuators | Home deployment, must be inherently safe |
| **Apollo** | Apptronik | ~30 | 1.73m, 73kg, 25kg payload | NASA partnership, industrial focus |

#### Humanoid Profile Requirements

Every humanoid profile MUST include:

```json
{
  "platform_class": "humanoid",
  "joints": [
    // ALL joints with real manufacturer specs:
    // - Position limits from URDF/MJCF (not approximations)
    // - Velocity limits from datasheet
    // - Torque limits from actuator specs
    // - Acceleration limits (computed from torque/inertia or datasheet)
  ],
  "stability": {
    "enabled": true,
    "support_polygon": [],           // Foot contact vertices
    "com_height_estimate": 0.0,      // Standing COM height
    "fall_detection_angle": 0.0,     // Max lean angle (radians)
    "recovery_margin": 0.0           // Safety margin inside polygon (meters)
  },
  "locomotion": {
    "max_base_linear_velocity": 0.0, // m/s
    "max_base_angular_velocity": 0.0,// rad/s
    "max_step_length": 0.0,          // meters
    "max_step_height": 0.0,          // meters (foot clearance)
    "max_ground_reaction_force": 0.0,// Newtons
    "friction_coefficient": 0.0,     // Static friction estimate
    "gait_cycle_bounds": [0.0, 0.0]  // Min/max gait period (seconds)
  },
  "manipulation": {
    "end_effectors": [
      {
        "name": "",
        "max_force": [0.0, 0.0, 0.0],       // N per axis
        "max_torque": [0.0, 0.0, 0.0],       // Nm per axis
        "max_grasp_force": 0.0,              // N
        "max_payload_kg": 0.0,
        "force_rate_limit": 0.0              // N/s
      }
    ]
  },
  "workspace": { "type": "aabb", "min": [], "max": [] },
  "exclusion_zones": [],
  "proximity_zones": [],
  "collision_pairs": [],
  "safe_stop_profile": {
    "strategy": "controlled_crouch",         // humanoids crouch, don't freeze
    "max_deceleration": 0.0,
    "target_joint_positions": {},
    "max_safe_stop_time_ms": 0               // Must reach safe state within this
  },
  "sensor_requirements": {
    "imu": "required",                       // Balance/orientation
    "foot_force_torque": "required",         // Ground contact
    "joint_encoders": "required",            // Position/velocity
    "joint_torque_sensors": "recommended",   // Effort feedback
    "wrist_force_torque": "recommended",     // Manipulation
    "proximity_sensors": "recommended",      // Human detection
    "tactile": "optional"                    // Grasp feedback
  }
}
```

### 1.2 Quadruped Robots

| Robot | Manufacturer | DOF | Key Specs |
|-------|-------------|-----|-----------|
| **Spot** | Boston Dynamics | 12 + arm (optional 7) | 32kg, autonomous inspection |
| **Go2 / B2** | Unitree | 12 | Go2: 15kg; B2: 70kg, high-payload |
| **ANYmal** | ANYbotics | 12 | 50kg, industrial inspection |
| **A1** | Unitree | 12 | 12kg, research platform |

#### Quadruped-Specific Checks
- 4-foot support polygon (stability check adapts to 3-foot during gait)
- Terrain adaptation (incline detection via IMU)
- Leg coordination (no two adjacent legs lifted simultaneously unless galloping)

### 1.3 Robotic Arms (Collaborative)

| Robot | Manufacturer | DOF | Key Specs |
|-------|-------------|-----|-----------|
| **Franka Panda** | Franka Emika | 7 | Torque-controlled, research standard |
| **UR10e / UR5e** | Universal Robots | 6 | Collaborative, ISO 10218 certified |
| **iiwa 14** | KUKA | 7 | 14kg payload, torque sensing |
| **Kinova Gen3** | Kinova | 7 | Lightweight, assistive robotics |
| **GoFa CRB 15000** | ABB | 6 | 5kg payload, collaborative |

#### Arm-Specific Checks
- No stability check needed (fixed base)
- Singularity proximity warning (near-singular Jacobian)
- Cable/hose routing constraints (joint combination limits)
- Payload compensation (torque limits adjusted by carried mass)

### 1.4 Mobile Manipulators

| Robot | Manufacturer | Config |
|-------|-------------|--------|
| **Spot + Arm** | Boston Dynamics | Quadruped + 7-DOF arm |
| **Stretch** | Hello Robot | Mobile base + telescoping arm |
| **TIAGo** | PAL Robotics | Differential drive + 7-DOF arm |

#### Mobile Manipulator-Specific Checks
- Combined base + arm workspace validation
- Tip-over stability (arm pose affects base stability)
- Base velocity limits change with arm extension

### 1.5 Dexterous Hands

| Hand | Manufacturer | DOF |
|------|-------------|-----|
| **Shadow Hand** | Shadow Robot | 24 |
| **Allegro Hand** | Wonik Robotics | 16 |
| **LEAP Hand** | Carnegie Mellon | 16 |
| **Ability Hand** | PSYONIC | 6 |

#### Hand-Specific Checks
- Per-finger force limits (crush prevention)
- Grasp stability (object must remain in grasp polygon)
- Pinch force limits for fragile objects
- Finger collision avoidance (self-collision between digits)

---

## 2. Expanded Safety Checks

### 2.1 Current Checks (P1-P10) -- IMPLEMENTED

| # | Check | What It Catches |
|---|-------|----------------|
| P1 | Joint position limits | Over-extension, mechanical damage |
| P2 | Joint velocity limits | Dangerous speed, whiplash |
| P3 | Joint torque limits | Motor burnout, structural failure |
| P4 | Joint acceleration limits | Jerk, instability, vibration |
| P5 | Workspace boundary | Reaching outside safe area |
| P6 | Exclusion zones | Human/obstacle collision |
| P7 | Self-collision distance | Robot hitting itself |
| P8 | Delta time bounds | Stale commands, control loop failure |
| P9 | Center-of-mass stability (ZMP) | Falling, tipping over |
| P10 | Proximity velocity scaling | Moving too fast near humans |

### 2.2 Expanded Checks (P11-P20) -- IMPLEMENTED

#### P11: End-Effector Force Limits
```
For each end-effector with force sensor data:
  |force[axis]| <= max_force[axis]   for axis in {x, y, z}
  |torque[axis]| <= max_torque[axis] for axis in {x, y, z}
```
**Catches**: Crushing objects, damaging surfaces, injuring humans during contact.
**Sensor**: Wrist F/T sensor (6-axis).
**Graceful degradation**: If no F/T data, check is SKIPPED (noted in verdict). Profile can mark F/T as `required` to make skip a failure.

#### P12: Grasp Force Limits
```
0 <= grasp_force <= max_grasp_force
If object_fragility is set: grasp_force <= fragility_limit
```
**Catches**: Crushing fragile objects (glass, electronics, food), insufficient grip (dropping heavy objects).
**Sensor**: Tactile/force sensors in gripper fingers.

#### P13: Force Rate-of-Change Limits
```
|force_new - force_old| / delta_time <= force_rate_limit
```
**Catches**: Impact forces (slamming into surfaces), sudden grasp/release that damages objects.
**Mirrors**: P4 (acceleration) but for forces instead of joint motion.

#### P14: Payload Validation
```
estimated_payload_kg <= end_effector.max_payload_kg
For each joint: adjusted_torque_limit = base_torque - payload_compensation(payload_kg)
```
**Catches**: Lifting objects too heavy for the actuators, torque limit violations under load.
**Sensor**: Wrist F/T sensor + gravity compensation calculation.

#### P15: Base Velocity Limits (Mobile Robots / Humanoid Locomotion)
```
|linear_velocity| <= max_base_linear_velocity
|angular_velocity| <= max_base_angular_velocity
```
**Catches**: Moving too fast for safe stopping distance, losing traction.
**Sensor**: IMU + odometry.

#### P16: Foot Clearance Validation (Legged Robots)
```
For each foot in swing phase:
  foot_height >= min_foot_clearance
  foot_height <= max_step_height
```
**Catches**: Tripping on obstacles, dragging feet, stomping.
**Sensor**: Joint encoders + forward kinematics, or direct foot position sensors.

#### P17: Ground Reaction Force Limits (Legged Robots)
```
For each foot in stance phase:
  |GRF| <= max_ground_reaction_force
  GRF_normal > 0  (foot must push down, not pull up)
```
**Catches**: Stomping (excessive vertical force), slipping (insufficient normal force for friction).
**Sensor**: Foot F/T sensors.

#### P18: Friction Cone Validation (Legged Robots)
```
For each foot in stance phase:
  |GRF_tangential| / GRF_normal <= friction_coefficient
```
**Catches**: Commands that would cause foot slip on the current surface.
**Sensor**: Foot F/T sensors.
**Note**: friction_coefficient should be conservative (0.4 for tile, 0.6 for carpet, 0.2 for wet surfaces).

#### P19: Step Length / Stride Limits (Legged Robots)
```
step_length <= max_step_length
step_width within [min_step_width, max_step_width]
```
**Catches**: Over-reaching during locomotion, splits, loss of balance from extreme stride.
**Sensor**: Joint encoders + forward kinematics.

#### P20: Heading Rate Limits (Legged / Mobile Robots)
```
|heading_rate| <= max_heading_rate
|heading_acceleration| <= max_heading_acceleration
```
**Catches**: Spinning too fast, losing balance during turns, dizzying nearby humans.
**Sensor**: IMU gyroscope.

### 2.3 Environmental Awareness Checks (P21-P25) -- IMPLEMENTED

#### P21: Incline / Terrain Safety
```
If IMU data available:
  pitch_angle <= max_safe_pitch
  roll_angle <= max_safe_roll
  If angle > warning_threshold: reduce velocity limits by terrain_scale_factor
```
**Catches**: Attempting to walk on too-steep inclines, tipping on ramps.
**Sensor**: IMU accelerometer + gyroscope.
**Default thresholds**: max_pitch = 15 degrees, max_roll = 10 degrees, warning at 8/5 degrees.

#### P22: Operating Temperature Bounds
```
For each joint actuator with temperature data:
  temperature <= max_operating_temperature
  If temperature > warning_threshold: reduce torque limits by thermal_derating_factor
```
**Catches**: Actuator overheating from sustained high-torque operation, thermal damage.
**Sensor**: Built-in motor temperature sensors.
**Graceful degradation**: Advisory only if no temperature data. Log warning.

#### P23: Battery / Power State Validation
```
battery_percentage >= min_operating_battery
If battery_percentage < low_battery_threshold:
  restrict to reduced_power_mode (lower velocity/torque limits)
If battery_percentage < critical_threshold:
  initiate safe_stop (robot must park before power loss)
```
**Catches**: Running out of power mid-task, brown-out during high-torque move.
**Sensor**: Battery management system telemetry.

#### P24: Communication Latency Bounds
```
roundtrip_latency <= max_acceptable_latency
If latency > warning_threshold: reduce velocity limits
If latency > critical_threshold: safe_stop
```
**Catches**: Network delays causing stale commands, cloud-to-edge latency spikes.
**Note**: Measured by Invariant's own heartbeat mechanism.

#### P25: Emergency Stop State
```
If e_stop_engaged: reject ALL commands, issue safe_stop
e_stop can only be cleared by physical button release + operator re-authorization
```
**Catches**: Software attempting to override hardware emergency stop.
**Sensor**: E-stop circuit state (digital input).
**Rule**: This check CANNOT be disabled in any profile. It is always active.

### 2.4 Check Summary

| Category | Checks | Count |
|----------|--------|-------|
| Joint safety | P1-P4 | 4 |
| Spatial safety | P5-P7 | 3 |
| Temporal safety | P8 | 1 |
| Stability | P9 | 1 |
| Human proximity | P10 | 1 |
| Force/contact | P11-P14 | 4 |
| Locomotion | P15-P20 | 6 |
| Environmental | P21-P25 | 5 |
| Authority | A1-A3 | 3 |
| Audit | L1-L4 | 4 |
| Actuation | M1 | 1 |
| Liveness | W1 | 1 |
| **Numbered invariants** | | **34** |
| Data quality pre-filters | SR1-SR2 (sensor range) | 2 |
| **Total checks in verdict** | | **36** |

---

## 3. Sensor Integration

Invariant does not read sensors directly. The cognitive layer or a sensor aggregation node provides sensor data as fields in the Command struct. Invariant validates the values.

### 3.1 Sensor Data in Command

```json
{
  "joint_states": [
    {
      "name": "left_hip_pitch",
      "position": 0.15,
      "velocity": 0.02,
      "effort": 45.0,
      "temperature": 42.5
    }
  ],
  "end_effector_positions": [
    { "name": "left_hand", "position": [0.3, 0.1, 0.9] }
  ],
  "end_effector_forces": [
    {
      "name": "left_hand",
      "force": [10.0, 2.0, -5.0],
      "torque": [0.5, 0.3, 0.1],
      "grasp_force": 15.0
    }
  ],
  "center_of_mass": [0.01, 0.0, 0.92],
  "imu": {
    "orientation_euler": [0.02, 0.01, 0.0],
    "angular_velocity": [0.001, 0.002, 0.0],
    "linear_acceleration": [0.1, 0.0, 9.78]
  },
  "locomotion_state": {
    "base_position": [0.0, 0.0, 0.92],
    "base_velocity": [0.5, 0.0, 0.0],
    "base_angular_velocity": [0.0, 0.0, 0.05],
    "feet": [
      {
        "name": "left_foot",
        "position": [-0.1, 0.1, 0.0],
        "in_contact": true,
        "ground_reaction_force": [2.0, 1.0, 280.0]
      },
      {
        "name": "right_foot",
        "position": [0.3, -0.1, 0.05],
        "in_contact": false,
        "ground_reaction_force": null
      }
    ]
  },
  "battery_state": {
    "percentage": 72.0,
    "voltage": 48.2,
    "current": -12.5
  },
  "e_stop_engaged": false,
  "estimated_payload_kg": 2.3
}
```

### 3.2 Sensor Validation Rules

| Sensor | Validation | Action on Missing |
|--------|-----------|-------------------|
| Joint encoders (position/velocity) | Always required | REJECT command |
| Joint effort | Required if P3 enabled | Skip P3, note in verdict |
| End-effector positions | Required if P5/P6/P7/P10 enabled | Skip spatial checks, note in verdict |
| End-effector F/T | Required if P11/P13 enabled | Skip force checks, note in verdict |
| Grasp force | Required if P12 enabled | Skip grasp check, note in verdict |
| IMU | Required if P21 enabled | Skip terrain check, note in verdict |
| Foot F/T | Required if P17/P18 enabled | Skip GRF checks, note in verdict |
| Center of mass | Required if P9 enabled | Skip stability, note in verdict |
| Battery state | Required if P23 enabled | Skip battery check, log warning |
| E-stop | Always checked if present | If field missing, log warning |
| Temperature | Advisory | Skip P22, log warning |

**Rule: Missing required sensor data for an enabled check causes the check to report `skipped` in the verdict. The profile's `sensor_requirements` field determines whether a skip is treated as PASS (graceful degradation) or FAIL (strict mode).**

### 3.3 Sensor Integrity

Phase 2 items — staleness and signed data are implemented; range validation and fusion are deferred:
- ~~Sensor staleness detection (reject if sensor timestamp > max_sensor_age)~~ ✓ (Step 65/100 — `check_sensor_freshness` with configurable `max_age_ms`)
- ~~Sensor range validation (reject obviously invalid readings: IMU reporting 50g, temperature of -200C)~~ ✓ (Step 108 — `check_sensor_range` in `environment.rs` rejects IMU > ±π rad, temperature below absolute zero or > 1000°C, battery outside [0,100]%, negative latency)
- ~~Signed sensor data (sensors sign their readings, Invariant verifies -- for zero-trust sensor integrity)~~ ✓ (Step 64 — `SignedSensorReading` with Ed25519 verification via `SensorTrustPolicy`)
- Sensor fusion consistency (IMU vs joint encoder vs F/T agreement within tolerance) — deferred

---

## 4. Expanded Test Matrix

### 4.1 Per-Platform Test Suite

Every robot profile gets the following test categories. Numbers are minimum test episodes per category.

#### Joint Safety Tests (per platform)
| Test ID | Scenario | Expected | Count |
|---------|----------|----------|-------|
| J-01 | All joints at exact min limit | PASS | 100 |
| J-02 | All joints at exact max limit | PASS | 100 |
| J-03 | Single joint 0.001 rad below min | REJECT (P1) | 100 per joint |
| J-04 | Single joint 0.001 rad above max | REJECT (P1) | 100 per joint |
| J-05 | All joints at 99% of position range | PASS | 1,000 |
| J-06 | Random valid positions | PASS | 10,000 |
| J-07 | Velocity at exactly max_velocity | PASS | 100 per joint |
| J-08 | Velocity at max_velocity + epsilon | REJECT (P2) | 100 per joint |
| J-09 | Velocity at max_velocity * 2 | REJECT (P2) | 100 per joint |
| J-10 | Torque at exactly max_torque | PASS | 100 per joint |
| J-11 | Torque at max_torque + epsilon | REJECT (P3) | 100 per joint |
| J-12 | Acceleration at max + epsilon | REJECT (P4) | 100 per joint |
| J-13 | NaN in position field | REJECT (P1) | 100 |
| J-14 | Infinity in velocity field | REJECT (P2) | 100 |
| J-15 | Negative zero in effort | PASS | 100 |
| J-16 | Largest representable f64 | REJECT | 100 |
| J-17 | Smallest subnormal f64 | PASS (near zero is valid) | 100 |
| J-18 | All joints moving at max velocity simultaneously | PASS | 1,000 |
| J-19 | Rapid direction reversal (max accel) | Check P4 boundary | 1,000 |
| J-20 | Gradual drift: 0.0001 rad/step beyond limit | REJECT on first violation | 10,000 |

#### Spatial Safety Tests (per platform)
| Test ID | Scenario | Expected | Count |
|---------|----------|----------|-------|
| S-01 | End-effector at workspace boundary | PASS | 1,000 |
| S-02 | End-effector 1mm outside workspace | REJECT (P5) | 1,000 |
| S-03 | End-effector inside each exclusion zone | REJECT (P6) | 100 per zone |
| S-04 | End-effector 1mm outside each exclusion zone | PASS | 100 per zone |
| S-05 | Collision pair at min_distance | PASS | 100 per pair |
| S-06 | Collision pair at min_distance - epsilon | REJECT (P7) | 100 per pair |
| S-07 | All end-effectors at workspace center | PASS | 1,000 |
| S-08 | End-effector in overlapping zone boundaries | Correct zone detected | 1,000 |
| S-09 | NaN in end-effector position | REJECT | 100 |
| S-10 | End-effector at [0,0,0] (ground level) | Profile-dependent | 100 |

#### Stability Tests (legged platforms only)
| Test ID | Scenario | Expected | Count |
|---------|----------|----------|-------|
| ST-01 | COM at polygon centroid | PASS (P9) | 1,000 |
| ST-02 | COM at polygon edge | PASS (P9, boundary) | 1,000 |
| ST-03 | COM 1mm outside polygon | REJECT (P9) | 1,000 |
| ST-04 | COM shifting during single-leg stance | Reduced polygon | 5,000 |
| ST-05 | Dynamic stability during walking gait | Track through gait cycle | 10,000 |
| ST-06 | Recovery from push (external disturbance) | Must stay in polygon or safe-stop | 5,000 |
| ST-07 | Standing on incline (5/10/15/20 degrees) | Adjusted polygon | 2,000 |
| ST-08 | Carrying payload shifts COM | Adjusted COM check | 2,000 |
| ST-09 | One foot slipping (reduced friction) | P18 catches slip | 2,000 |
| ST-10 | Transition sit-to-stand | COM trajectory validated | 2,000 |

#### Locomotion Tests (legged platforms only)
| Test ID | Scenario | Expected | Count |
|---------|----------|----------|-------|
| L-01 | Walking at max velocity on flat ground | PASS | 10,000 |
| L-02 | Walking at max_velocity + 10% | REJECT (P15) | 1,000 |
| L-03 | Step length at max | PASS (P19) | 1,000 |
| L-04 | Step length at max + epsilon | REJECT (P19) | 1,000 |
| L-05 | Foot clearance below minimum | REJECT (P16) | 1,000 |
| L-06 | Normal walking gait cycle | All checks PASS | 50,000 |
| L-07 | Running gait (if supported) | All checks PASS | 10,000 |
| L-08 | Turning at max heading rate | PASS (P20) | 5,000 |
| L-09 | Turning at max heading rate + epsilon | REJECT (P20) | 1,000 |
| L-10 | Walking on 10-degree incline | P21 terrain check | 5,000 |
| L-11 | Walking on 20-degree incline | REJECT (P21, too steep) | 1,000 |
| L-12 | Transition: walk to stop | Safe deceleration | 5,000 |
| L-13 | Transition: stand to walk | Smooth acceleration | 5,000 |
| L-14 | Stair climbing (if supported) | Step height validation | 5,000 |
| L-15 | Stair descending | Forward stability | 5,000 |

#### Manipulation Tests (platforms with arms/hands)
| Test ID | Scenario | Expected | Count |
|---------|----------|----------|-------|
| M-01 | Grasp object within force limits | PASS | 10,000 |
| M-02 | Grasp at max_grasp_force | PASS (P12) | 1,000 |
| M-03 | Grasp at max_grasp_force + epsilon | REJECT (P12) | 1,000 |
| M-04 | Lift object within payload limit | PASS (P14) | 5,000 |
| M-05 | Lift object exceeding payload limit | REJECT (P14) | 1,000 |
| M-06 | Contact with surface (controlled) | P11 force limits | 5,000 |
| M-07 | Impact with surface (sudden) | REJECT (P13, force rate) | 1,000 |
| M-08 | Handoff object to human | Force limits during transfer | 5,000 |
| M-09 | Bimanual coordination (both arms) | Both validated | 5,000 |
| M-10 | Carrying object changes COM | P9 stability updated | 5,000 |
| M-11 | Place object gently | Force rate within limits | 5,000 |
| M-12 | Tool use (drill, screwdriver) | Torque/force limits | 5,000 |

#### Authority / Security Tests (all platforms)
| Test ID | Scenario | Expected | Count |
|---------|----------|----------|-------|
| A-01 | Valid PCA chain, authorized ops | PASS | 10,000 |
| A-02 | Forged signature in chain | REJECT | 1,000 |
| A-03 | Operations exceed granted scope | REJECT | 1,000 |
| A-04 | Expired PCA chain | REJECT | 1,000 |
| A-05 | Chain with widened operations (A2 violation) | REJECT | 1,000 |
| A-06 | Replayed command (old timestamp) | REJECT | 1,000 |
| A-07 | Command for wrong robot profile | REJECT | 1,000 |
| A-08 | Empty required_ops | REJECT | 1,000 |
| A-09 | Cross-operator chain splice | REJECT | 1,000 |
| A-10 | Prompt injection in metadata | No effect on validation | 10,000 |
| A-11 | Giant PCA chain (memory DoS) | REJECT (size cap) | 1,000 |
| A-12 | NaN/Inf in authority fields | REJECT | 1,000 |
| A-13 | Unicode attack in operation names | REJECT or safe handling | 1,000 |
| A-14 | Multi-agent handoff (cognitive layer swap) | New chain required | 5,000 |
| A-15 | Gradual authority escalation over time | Each command independently checked | 10,000 |

#### Watchdog / Liveness Tests (all platforms)
| Test ID | Scenario | Expected | Count |
|---------|----------|----------|-------|
| W-01 | Regular heartbeats (within timeout) | No safe-stop | 10,000 |
| W-02 | Missed heartbeat (timeout exceeded) | Safe-stop triggered | 1,000 |
| W-03 | Heartbeat resumes after timeout | Safe-stop holds until reset | 1,000 |
| W-04 | Cognitive layer crash (no heartbeats) | Safe-stop within timeout_ms | 1,000 |
| W-05 | Heartbeat with wrong key | REJECT heartbeat | 1,000 |
| W-06 | Watchdog during active manipulation | Graceful stop (don't drop object) | 1,000 |
| W-07 | Watchdog during locomotion | Controlled crouch/stop | 1,000 |
| W-08 | Rapid heartbeat flooding | Rate limited, no DoS | 1,000 |

#### Environmental Tests (all platforms where applicable)
| Test ID | Scenario | Expected | Count |
|---------|----------|----------|-------|
| E-01 | Normal operating temperature | PASS | 1,000 |
| E-02 | Actuator approaching thermal limit | Torque derated (P22) | 1,000 |
| E-03 | Actuator at thermal limit | REJECT high-torque commands | 1,000 |
| E-04 | Battery at 50% | Normal operation | 1,000 |
| E-05 | Battery at 15% (low) | Reduced power mode (P23) | 1,000 |
| E-06 | Battery at 5% (critical) | Safe-stop initiated (P23) | 1,000 |
| E-07 | Communication latency spike | Velocity reduced (P24) | 1,000 |
| E-08 | Communication loss | Safe-stop via watchdog | 1,000 |
| E-09 | E-stop engaged | ALL commands rejected (P25) | 1,000 |
| E-10 | E-stop release + re-auth | Commands resume after auth | 1,000 |

### 4.2 Cross-Platform Stress Tests

These tests run across ALL platforms simultaneously.

| Test ID | Scenario | Count |
|---------|----------|-------|
| X-01 | 1000 commands/sec sustained for 60 seconds | 60,000 |
| X-02 | Alternating valid/invalid commands (50/50) | 100,000 |
| X-03 | 100% invalid commands (fuzzer output) | 100,000 |
| X-04 | Identical command replayed 10,000 times | 10,000 |
| X-05 | Profile hot-swap mid-stream | 10,000 |
| X-06 | Maximum-size command payload (4KB limit) | 10,000 |
| X-07 | Minimum valid command (required fields only) | 10,000 |
| X-08 | Mixed robot profiles in single audit log | 10,000 |
| X-09 | Audit log at 1M entries, verify chain | 1 (1M steps) |
| X-10 | 24-hour continuous operation simulation | 1 (8.64M steps at 100Hz) |

### 4.3 Adversarial / Red Team Tests

| Category | Attack Types | Count |
|----------|-------------|-------|
| Protocol-level (PA) | Boundary probing, epsilon escalation, NaN/Inf injection, type confusion, JSON bombs, deserialization gadgets | 500,000 |
| Authority chain (AA) | Signature forgery, key substitution, chain truncation, provenance mutation, wildcard exploit, cross-chain splice | 500,000 |
| System-level (SA) | Profile tampering, key exfiltration attempts, audit tampering, resource exhaustion, clock manipulation | 250,000 |
| Cognitive escape (CE) | Gradual drift, timing exploitation, semantic confusion, authority laundering, distraction flooding, multi-agent coordination | 250,000 |
| **Total adversarial** | | **1,500,000** |

### 4.4 Total Test Matrix Summary

| Category | Episodes | Platforms |
|----------|----------|-----------|
| Joint safety | ~500,000 | All |
| Spatial safety | ~200,000 | All |
| Stability | ~200,000 | Humanoids + Quadrupeds |
| Locomotion | ~500,000 | Humanoids + Quadrupeds |
| Manipulation | ~300,000 | Humanoids + Arms + Mobile Manipulators |
| Authority/Security | ~500,000 | All |
| Watchdog/Liveness | ~100,000 | All |
| Environmental | ~100,000 | All |
| Cross-platform stress | ~400,000 | All |
| Adversarial/Red team | 1,500,000 | All |
| Standard operation (coverage) | ~5,700,000 | Distributed across platforms |
| **TOTAL** | **~10,000,000** | **17+ robot profiles** |

---

## 5. Isaac Sim Campaign Architecture

### 5.1 Overview

```
+------------------+     +------------------+     +------------------+
|                  |     |                  |     |                  |
|  Isaac Lab       |     |  Invariant       |     |  Data Collector  |
|  (Python/GPU)    | --> |  (Rust binary)   | --> |  (Python)        |
|                  |     |                  |     |                  |
|  Physics sim     |     |  Validate cmd    |     |  Save traces     |
|  Sensor sim      |     |  Sign verdict    |     |  Save seeds      |
|  Robot model     |     |  Audit log       |     |  Save configs    |
|  Environment     |     |  Watchdog        |     |  Aggregate stats |
|                  |     |                  |     |                  |
+------------------+     +------------------+     +------------------+
        |                         |                        |
        v                         v                        v
  GPU (PhysX)              CPU (pure Rust)          Disk / S3
```

### 5.2 Communication Protocol

Invariant runs as a subprocess or Unix socket server. Isaac Lab communicates via newline-delimited JSON over stdin/stdout or Unix socket.

```
Isaac Lab --> Invariant:  {"command": {...}, "profile": "humanoid_28dof"}
Invariant --> Isaac Lab:  {"verdict": {...}, "signed_actuation": {...}}
```

**Latency budget**: < 1ms per validation (physics sim runs at 200Hz = 5ms per step, Invariant must complete well within one step).

### 5.3 Isaac Lab Integration Code

```python
# invariant_bridge.py -- Isaac Lab <-> Invariant bridge

import subprocess
import json
import numpy as np
from dataclasses import dataclass, asdict
from typing import Optional

class InvariantBridge:
    """Bridge between Isaac Lab environment and Invariant validator."""

    def __init__(self, binary_path: str = "invariant",
                 profile: str = "humanoid_28dof",
                 key_file: str = "keys/validator.json",
                 socket_mode: bool = False,
                 socket_path: str = "/tmp/invariant.sock"):
        self.profile = profile
        self.socket_mode = socket_mode

        if socket_mode:
            # Unix socket mode for high-throughput
            self.proc = subprocess.Popen(
                [binary_path, "serve", "--trust-plane",
                 "--profile", profile,
                 "--key-file", key_file,
                 "--socket", socket_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
        else:
            # Stdin/stdout mode for simplicity
            self.proc = subprocess.Popen(
                [binary_path, "validate", "--mode", "guardian",
                 "--profile", profile,
                 "--key-file", key_file,
                 "--stdin"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

    def validate(self, command: dict) -> dict:
        """Send command to Invariant, receive verdict."""
        line = json.dumps(command) + "\n"
        self.proc.stdin.write(line.encode())
        self.proc.stdin.flush()
        response = self.proc.stdout.readline()
        return json.loads(response)

    def build_command(self, obs: dict, action: np.ndarray,
                      joint_names: list, dt: float,
                      sequence: int, pca_chain_b64: str,
                      required_ops: list,
                      ee_positions: Optional[dict] = None,
                      com: Optional[np.ndarray] = None,
                      ee_forces: Optional[dict] = None,
                      imu: Optional[dict] = None,
                      locomotion: Optional[dict] = None,
                      battery: Optional[dict] = None,
                      e_stop: bool = False,
                      payload_kg: Optional[float] = None) -> dict:
        """Build Invariant command from Isaac Lab observation + action."""

        joint_states = []
        for i, name in enumerate(joint_names):
            joint_states.append({
                "name": name,
                "position": float(obs["joint_pos"][i]),
                "velocity": float(obs["joint_vel"][i]),
                "effort": float(action[i])  # commanded torque
            })

        command = {
            "timestamp": self._iso_now(),
            "source": "isaac_lab",
            "sequence": sequence,
            "joint_states": joint_states,
            "delta_time": float(dt),
            "authority": {
                "pca_chain": pca_chain_b64,
                "required_ops": required_ops
            },
            "metadata": {
                "env_id": str(obs.get("env_id", 0)),
                "episode": str(obs.get("episode", 0))
            }
        }

        # Optional sensor data
        if ee_positions is not None:
            command["end_effector_positions"] = ee_positions
        if com is not None:
            command["center_of_mass"] = com.tolist()
        if ee_forces is not None:
            command["end_effector_forces"] = ee_forces
        if imu is not None:
            command["imu"] = imu
        if locomotion is not None:
            command["locomotion_state"] = locomotion
        if battery is not None:
            command["battery_state"] = battery
        if e_stop:
            command["e_stop_engaged"] = True
        if payload_kg is not None:
            command["estimated_payload_kg"] = payload_kg

        return command
```

### 5.4 Campaign Runner

```python
# campaign_runner.py -- orchestrates the full 10M campaign

import os
import json
import gzip
import hashlib
import time
from pathlib import Path

class CampaignRunner:
    """Runs the full simulation campaign and collects results."""

    def __init__(self, output_dir: str, shard_id: int = 0,
                 total_shards: int = 1):
        self.output_dir = Path(output_dir)
        self.shard_id = shard_id
        self.total_shards = total_shards
        self.results = []
        self.stats = {
            "total": 0, "approved": 0, "rejected": 0,
            "checks_fired": {}, "rejection_reasons": {},
            "latencies_us": []
        }

        # Create output structure
        (self.output_dir / "traces").mkdir(parents=True, exist_ok=True)
        (self.output_dir / "seeds").mkdir(parents=True, exist_ok=True)
        (self.output_dir / "audit").mkdir(parents=True, exist_ok=True)

    def run_episode(self, env, bridge, scenario, episode_id: int,
                    seed: int, max_steps: int = 200):
        """Run a single episode and record everything."""

        # Save seed for deterministic replay
        seed_record = {
            "episode_id": episode_id,
            "seed": seed,
            "scenario": scenario.name,
            "profile": bridge.profile,
            "shard": self.shard_id
        }

        env.seed(seed)
        obs = env.reset()
        trace_steps = []

        for step in range(max_steps):
            # Cognitive layer generates action (scenario-dependent)
            action = scenario.generate_action(obs, step)

            # Build command with all available sensor data
            command = bridge.build_command(
                obs=obs,
                action=action,
                joint_names=env.joint_names,
                dt=env.dt,
                sequence=episode_id * max_steps + step,
                pca_chain_b64=scenario.pca_chain,
                required_ops=scenario.required_ops,
                ee_positions=self._extract_ee_positions(obs),
                com=obs.get("com_position"),
                ee_forces=self._extract_ee_forces(obs),
                imu=self._extract_imu(obs),
                locomotion=self._extract_locomotion(obs),
                battery=obs.get("battery"),
                e_stop=obs.get("e_stop", False),
                payload_kg=obs.get("payload_kg")
            )

            # Validate through Invariant
            t0 = time.monotonic_ns()
            verdict = bridge.validate(command)
            latency_us = (time.monotonic_ns() - t0) / 1000

            # Record step
            trace_steps.append({
                "step": step,
                "command_hash": self._hash(command),
                "verdict_approved": verdict["verdict"]["approved"],
                "checks": verdict["verdict"]["checks"],
                "latency_us": latency_us,
                "seed": seed
            })

            # Update stats
            self._update_stats(verdict, latency_us)

            # Apply action or safe-stop based on verdict
            if verdict["verdict"]["approved"]:
                obs = env.step(action)
            else:
                obs = env.step(env.zero_action())  # Safe: no movement
                if scenario.stop_on_reject:
                    break

        # Save trace (compressed)
        trace_path = self.output_dir / "traces" / f"ep_{episode_id:08d}.json.gz"
        with gzip.open(trace_path, "wt") as f:
            json.dump({"episode_id": episode_id, "steps": trace_steps}, f)

        # Save seed
        seed_path = self.output_dir / "seeds" / f"ep_{episode_id:08d}.json"
        with open(seed_path, "w") as f:
            json.dump(seed_record, f)

        return trace_steps

    def write_summary(self):
        """Write campaign summary statistics."""
        summary = {
            "shard_id": self.shard_id,
            "total_commands": self.stats["total"],
            "approved": self.stats["approved"],
            "rejected": self.stats["rejected"],
            "approval_rate": self.stats["approved"] / max(self.stats["total"], 1),
            "rejection_reasons": self.stats["rejection_reasons"],
            "latency_p50_us": self._percentile(self.stats["latencies_us"], 50),
            "latency_p99_us": self._percentile(self.stats["latencies_us"], 99),
            "latency_p999_us": self._percentile(self.stats["latencies_us"], 99.9),
            "false_negatives": 0,  # Updated by post-analysis
            "false_positives": 0   # Updated by post-analysis
        }
        with open(self.output_dir / "summary.json", "w") as f:
            json.dump(summary, f, indent=2)
```

### 5.5 Scenario Definitions for Isaac Lab

```python
# scenarios.py -- what the cognitive layer does in each scenario

class BaselineScenario:
    """Normal operation. Valid commands within all limits."""
    name = "baseline"
    # Expected: 100% approval rate
    # Tests: all checks pass under normal conditions

class AggressiveScenario:
    """Push joints to 95-100% of limits. Near-boundary operation."""
    name = "aggressive"
    # Expected: ~95% approval (some boundary violations)
    # Tests: P1-P4 boundary precision

class HumanProximityScenario:
    """Human enters workspace during operation."""
    name = "human_proximity"
    # Expected: velocity scaling kicks in (P10)
    # Tests: ISO/TS 15066 compliance, dynamic proximity zones

class FallingRecoveryScenario:
    """External push or slip causes instability."""
    name = "falling_recovery"
    # Expected: P9 catches COM outside polygon, safe-stop triggers
    # Tests: stability check, watchdog, safe-stop timing

class ManipulationScenario:
    """Pick up, carry, and place objects of various weights."""
    name = "manipulation"
    # Expected: force/payload checks (P11-P14)
    # Tests: grasp force, payload limits, force rate

class StairClimbingScenario:
    """Navigate stairs up and down."""
    name = "stair_climbing"
    # Expected: P16 foot clearance, P21 incline check
    # Tests: locomotion checks during complex terrain

class PromptInjectionScenario:
    """LLM receives adversarial prompt, generates unsafe commands."""
    name = "prompt_injection"
    # Expected: 100% rejection of unsafe commands
    # Tests: authority chain blocks unauthorized operations

class WatchdogTimeoutScenario:
    """Cognitive layer crashes or hangs."""
    name = "watchdog_timeout"
    # Expected: safe-stop within watchdog_timeout_ms
    # Tests: W1 liveness, safe-stop execution

class MultiAgentHandoffScenario:
    """Control transfers between different AI systems."""
    name = "multi_agent_handoff"
    # Expected: new authority chain required for each agent
    # Tests: A1-A3 across agent boundaries

class DegradedSensorScenario:
    """Some sensors fail or report stale data."""
    name = "degraded_sensor"
    # Expected: graceful degradation per sensor_requirements
    # Tests: missing sensor handling, check skipping behavior

class ThermalStressScenario:
    """Sustained high-torque operation causes heating."""
    name = "thermal_stress"
    # Expected: P22 thermal derating, eventual safe-stop
    # Tests: temperature monitoring, torque reduction

class LowBatteryScenario:
    """Battery draining during operation."""
    name = "low_battery"
    # Expected: P23 reduced power mode, then safe-stop
    # Tests: battery monitoring, graceful shutdown
```

---

## 6. RunPod Execution Plan

### 6.1 Infrastructure

```
RunPod Configuration:
  GPU:     8x A40 (48GB VRAM each)
  vCPU:    32 cores per pod (256 total)
  RAM:     128 GB per pod
  Storage: 500 GB NVMe per pod
  Cost:    ~$0.76/hr per A40 = ~$6.08/hr total
```

### 6.2 Container Setup

```dockerfile
# Dockerfile.campaign
FROM nvcr.io/nvidia/isaac-sim:4.5.0

# Install Rust toolchain for Invariant
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Build Invariant from source
COPY . /opt/invariant
WORKDIR /opt/invariant
RUN cargo build --release
RUN cp target/release/invariant /usr/local/bin/

# Install Python campaign runner
RUN pip install numpy pyyaml boto3

# Pre-generate campaign keys
RUN invariant keygen --output /opt/keys/validator.json
RUN invariant keygen --output /opt/keys/operator.json --export-pub

ENTRYPOINT ["python", "/opt/invariant/campaigns/run.py"]
```

### 6.3 Execution Timeline

```
Phase 0: Smoke Test (local, no GPU needed)
  - Run dry-run campaign: invariant campaign --dry-run --episodes 1000
  - Verify all 4 built-in profiles produce expected results
  - Verify trace collection and replay
  - Duration: ~5 minutes
  - Cost: $0

Phase 1: Integration Test (1x RunPod A40) -- 100 episodes
  - Run 100 Isaac Lab episodes with Invariant bridge
  - Verify sensor data flows correctly
  - Verify verdict collection and seed saving
  - Replay 5 episodes to confirm determinism
  - CHECK: Are commands being built correctly from Isaac Lab obs?
  - CHECK: Are seeds saving and replaying deterministically?
  - CHECK: Are traces, audit logs, and configs all being collected?
  - Duration: ~10 minutes
  - Cost: ~$0.15
  - GATE: Do not proceed until all checks pass. Fix any issues locally,
    re-deploy container, re-run Phase 1.

Phase 2: Validation Run (1x RunPod A40) -- 1,000 episodes
  - Run 1,000 Isaac Lab episodes across multiple scenarios
  - Check approval/rejection rates match expectations per scenario
  - Verify latency stays under 1ms p99
  - Review every unexpected rejection manually (at 1K this is feasible)
  - Verify audit chain integrity on the full 1K run
  - Run all 3 eval presets against collected traces
  - CHECK: Does safety-check preset pass on baseline scenarios?
  - CHECK: Does completeness-check find all 11 checks per verdict?
  - CHECK: Are rejection reasons correct (right check caught right violation)?
  - CHECK: Is data pipeline to S3/HuggingFace working?
  - Duration: ~15 minutes
  - Cost: ~$0.20
  - GATE: Do not proceed until all checks pass.

>>> FULL STOP -- MANUAL REVIEW <<<

  Before Phase 3, sit down and manually review:
    1. Sample 50 approved traces -- are they genuinely safe?
    2. Sample 50 rejected traces -- are the rejections correct?
    3. Replay 10 random episodes from seed -- identical results?
    4. Review aggregate stats -- do scenario distributions make sense?
    5. Check storage estimates -- will 10M fit in budget?
    6. Verify proof package structure generates correctly from 1K data

  This pause exists because 10M episodes costs real money and takes
  real time. Finding a bug at 10M that you could have caught at 1K
  means re-running the entire campaign. Take the time here.

  Only proceed when you are 100% confident the pipeline is correct.

Phase 3: Full Campaign (8x RunPod A40) -- 10,000,000 episodes
  - Run 10,000,000 episodes (1.25M per shard)
  - All 17+ robot profiles
  - All scenario types
  - All adversarial test categories
  - Monitor progress via shard status files
  - Duration: ~3-4 hours
  - Cost: ~$20-25

Phase 4: Analysis & Proof Package
  - Aggregate results from all shards
  - Verify audit chain integrity across all 10M entries
  - Generate statistical report
  - Run all eval presets against full dataset
  - Record demo videos (re-run 10 selected episodes with rendering)
  - Build final proof package (see Section 7)
  - Duration: ~2 hours (1 GPU for video recording)
  - Cost: ~$2
```

### 6.4 Data Collection Per Step

Every simulation step produces this record:

```json
{
  "episode_id": 4827391,
  "step": 42,
  "seed": 98234751,
  "profile": "humanoid_28dof",
  "scenario": "baseline",
  "timestamp_sim": "2026-04-01T12:00:00.042Z",
  "timestamp_wall": "2026-04-01T12:34:56.789Z",

  "command_hash": "sha256:a1b2c3...",
  "verdict": {
    "approved": true,
    "checks": [
      {"name": "authority", "passed": true},
      {"name": "joint_limits", "passed": true},
      {"name": "velocity_limits", "passed": true},
      {"name": "torque_limits", "passed": true},
      {"name": "acceleration_limits", "passed": true},
      {"name": "workspace_bounds", "passed": true},
      {"name": "exclusion_zones", "passed": true},
      {"name": "self_collision", "passed": true},
      {"name": "delta_time", "passed": true},
      {"name": "stability", "passed": true},
      {"name": "proximity_velocity", "passed": true}
    ]
  },

  "audit_entry_hash": "sha256:d4e5f6...",
  "validation_latency_us": 312,
  "action_applied": true
}
```

**Storage estimate for 10M episodes x 200 steps/episode:**
- Compressed traces: ~50-100 GB
- Seeds/configs: ~2 GB
- Audit logs: ~20 GB
- Summary statistics: ~100 MB
- **Total: ~75-125 GB**

### 6.5 Video Recording (Post-Campaign)

After the campaign completes, select episodes for video demo:

| Video | Episode Type | Duration | Purpose |
|-------|-------------|----------|---------|
| Hero video | Normal humanoid operation | 60-90s | README header, shows Invariant working |
| Safety catch | Joint limit violation blocked | 15s | P1-P4 in action |
| Human proximity | Velocity scaling near human | 15s | P10, ISO compliance |
| Prompt injection | LLM generates unsafe command, blocked | 15s | Authority chain protection |
| Watchdog save | Cognitive crash, safe-stop | 15s | Watchdog in action |
| Stability save | Push recovery, COM check | 15s | P9, fall prevention |
| Force limit | Excessive grasp blocked | 15s | P12, object protection |
| Multi-robot | Two humanoids, independent validation | 30s | Scale demo |
| Full audit | Verification of 10M audit entries | 15s | Tamper-proof trail |
| Speed demo | Validation latency visualization | 15s | Sub-ms performance |

**Recording process:**
```bash
# Re-run specific episode with rendering (same seed = identical physics)
python replay.py \
  --seed 98234751 \
  --profile humanoid_28dof \
  --scenario human_proximity \
  --render \
  --camera-preset front_45deg \
  --output videos/human_proximity_demo.mp4 \
  --overlay-verdicts  # Show accept/reject overlay in real-time
```

---

## 7. Proof Package

The final deliverable that proves Invariant works.

### 7.1 Contents

```
invariant-proof/
  manifest.json              # Signed package metadata
  README.md                  # Human-readable summary

  campaign/
    config.yaml              # Exact campaign configuration
    profiles/                # All 17+ robot profiles used
    keys/                    # Public keys only (for verification)
    container_hash.txt       # SHA-256 of Docker image
    invariant_binary_hash.txt# SHA-256 of compiled binary

  results/
    summary.json             # Aggregate statistics
    per_profile/             # Per-robot results
      humanoid_28dof.json
      optimus_gen2.json
      figure_02.json
      ...
    per_scenario/            # Per-scenario results
      baseline.json
      prompt_injection.json
      ...
    per_check/               # Per-check pass/fail distribution
      joint_limits.json
      velocity_limits.json
      ...
    latency_distribution.json # p50, p95, p99, p999, max

  adversarial/
    protocol_attacks.json    # PA results
    authority_attacks.json   # AA results
    system_attacks.json      # SA results
    cognitive_escapes.json   # CE results
    total_bypass_rate.json   # The money number: 0.000%

  audit/
    chain_verification.json  # Full hash-chain verification result
    merkle_root.txt          # Root hash of all audit entries
    sample_entries/          # 100 random verified entries

  integrity/
    all_seeds.json.gz        # Every seed for full reproducibility
    shard_checksums.json     # SHA-256 of each shard's output

  videos/
    hero_demo.mp4
    safety_catches/
      joint_limit.mp4
      human_proximity.mp4
      prompt_injection.mp4
      watchdog.mp4
      stability.mp4
      force_limit.mp4

  compliance/
    iec_61508_mapping.md     # Functional safety
    iso_10218_mapping.md     # Robot safety
    iso_ts_15066_mapping.md  # Collaborative robots
    nist_ai_600_1_mapping.md # AI safety
```

### 7.2 Statistical Claims

With 10,000,000 validated decisions and 0 bypass events:

| Metric | Value |
|--------|-------|
| Total commands validated | 10,000,000 |
| Total approved (valid commands) | ~8,500,000 |
| Total rejected (invalid commands) | ~1,500,000 |
| False negatives (unsafe approved) | 0 |
| False positives (safe rejected) | To be measured |
| **Bypass rate** | **0.000%** |
| 95% confidence upper bound | < 0.0000293% |
| 99% confidence upper bound | < 0.0000449% |
| Equivalent: "fewer than 1 in 3.3 million" | |
| Robot profiles tested | 17+ |
| Unique scenarios | 12+ |
| Adversarial attack classes | 50+ |
| Mean validation latency | < 400 us |
| p99 validation latency | < 800 us |
| Audit chain integrity | 100% verified |

---

## 8. What Must Be Built Before Simulations

### 8.1 Current State (Built and Tested)

| Component | Status | Tests |
|-----------|--------|-------|
| 25 physics checks (P1-P25) | Complete | 200+ tests |
| Ed25519 authority chain (A1-A3) | Complete | 50+ tests |
| Validator orchestrator (+ DoS caps, replay) | Complete | 30+ tests |
| Signed audit logger (L1-L4) | Complete | 20+ tests |
| Watchdog (W1) | Complete | 20+ tests |
| 10 robot profiles (humanoid, quadruped, Franka, UR10, UR10e×2, H1, G1, Spot, iiwa14) | Complete | 30+ tests |
| CLI (validate, keygen, audit, verify, inspect, eval, diff, campaign, serve, ...) | Complete | 176+ tests |
| Embedded trust plane (axum server + replay protection) | Complete | 15+ tests |
| Key management + COSE hardening | Complete | 40+ tests |
| 3 eval presets | Complete | 23+ tests |
| Dry-run campaign engine | Complete | 100+ tests |
| 14 simulation scenarios | Complete | 100+ tests |
| 27 fault injection types | Complete | 100+ tests |
| Digital twin divergence detection | Complete | 15+ tests |
| Multi-robot coordinator | Complete | 34+ tests |
| Threat scoring engine | Complete | 20+ tests |
| Proof package generator + verifier | Complete | 15+ tests |
| Sensor integrity (signed + freshness) | Complete | 15+ tests |
| **Total** | **1,767 tests passing** | **Clippy clean** |

### 8.2 Must Build for Isaac Sim Campaign

| Component | Priority | Status | Description |
|-----------|----------|--------|-------------|
| ~~**Isaac Lab bridge** (Python)~~ | P0 | ✅ Done (Step 69/85) | Python wrapper + Unix socket bridge in `invariant-sim::isaac::bridge` |
| ~~**Campaign runner** (Python)~~ | P0 | ✅ Done (Step 84) | Dry-run campaign engine with seeds, traces, audit, reporting |
| ~~**13+ new robot profiles**~~ | P0 | ✅ Done (10 profiles) | humanoid_28dof, franka_panda, quadruped_12dof, ur10, ur10e_haas_cell, ur10e_cnc_tending, unitree_h1, unitree_g1, spot, kuka_iiwa14 |
| **Isaac Lab task environments** | P0 | Pending | Custom Isaac Lab envs for each scenario (requires GPU/RunPod) |
| ~~**Stdin validation mode**~~ | P1 | ✅ Done (Step 59) | `invariant validate --stdin` reads JSON commands, writes verdicts |
| ~~**New physics checks (P11-P20)**~~ | P1 | ✅ Done (Steps 43-52) | Force, grasp, payload, locomotion, terrain — all 10 checks |
| ~~**Scenario generators**~~ | P1 | ✅ Done (Step 52/91/98) | 14 scenario types + 27 fault injection types in Rust |
| **Video replay script** | P2 | Pending | Re-run episode from seed with rendering + verdict overlay |
| ~~**Proof package generator**~~ | P2 | ✅ Done (Steps 70-71) | `invariant verify-package` assembles + verifies proof bundles |
| ~~**Environmental checks (P21-P25)**~~ | P2 | ✅ Done (Steps 90-95) | Temperature, battery, latency, e-stop, terrain |
| ~~**README with results**~~ | P2 | ✅ Done (Step 87) | README synced with full feature set |

### 8.3 Recommended Build Order

```
Week 1: Foundation
  Day 1-2: Stdin validation mode + Isaac Lab bridge (Python)
  Day 3-4: 3-4 new robot profiles (GR-1, Optimus, Figure 02, Spot)
  Day 5:   Campaign runner + local dry-run test (Phase 0)

Week 2: Scale
  Day 1-2: Isaac Lab task environments (walking, manipulation)
  Day 3:   Phase 1 on RunPod (100 episodes, verify pipeline)
  Day 4:   Phase 2 on RunPod (10K episodes, verify data)
  Day 5:   Fix issues found in Phase 1-2

Week 3: Campaign
  Day 1:   Remaining robot profiles
  Day 2:   P11-P14 force/manipulation checks
  Day 3:   Phase 3 on RunPod (100K episodes)
  Day 4-5: Phase 4 full campaign (10M episodes, 3-4 hours)

Week 4: Polish
  Day 1:   Analysis + proof package
  Day 2:   Record demo videos
  Day 3:   README + documentation
  Day 4-5: Review, polish, publish
```

### 8.4 Phase 0 Readiness Checklist

Before spending any money on RunPod, verify locally:

- [x] `cargo test` -- all 1,767+ tests pass
- [x] `cargo clippy` -- clean
- [x] `invariant validate` works with all 10 built-in profiles
- [x] `invariant campaign --dry-run` completes with configurable episodes
- [x] Dry-run traces can be loaded by `invariant eval`
- [x] All 14 scenario types produce expected approval/rejection patterns
- [x] All 27 fault injection types trigger expected check failures
- [x] Audit log verification passes after dry-run campaign
- [x] Stdin validation mode works (pipe JSON commands, get verdicts)
- [x] Isaac Lab bridge can build valid commands from mock observations (dry-run + bridge module)
- [x] Campaign runner saves seeds, traces, and configs correctly
- [x] Replay from seed produces identical trace

---

## 9. Success Criteria

The campaign succeeds when ALL of the following are true:

1. **Zero false negatives**: No unsafe command is approved across 10M+ decisions
2. **Deterministic replay**: Any episode can be reproduced from its seed
3. **Audit integrity**: 100% of audit chain hashes and signatures verify
4. **Latency**: p99 validation latency < 1ms
5. **Coverage**: All 17+ robot profiles tested with all applicable scenarios
6. **Adversarial resilience**: 0% bypass rate across 1.5M+ adversarial commands
7. **Graceful degradation**: Missing sensor data handled correctly (skip or fail per config)
8. **Watchdog reliability**: 100% of timeout events trigger safe-stop within configured window
9. **Multi-platform**: Results consistent across humanoid, quadruped, arm, and hand platforms
10. **Reproducible**: Full campaign reproducible from published seeds + configs + container image

If any criterion fails, the campaign is re-run after fixing the root cause. The proof is only valid with 100% of criteria met.
