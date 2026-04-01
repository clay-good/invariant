/-
  Invariant — Formal Specification: Domain Types
  Step 42: Lean 4 formalization of all 29 invariants.

  These types model the core domains of the Invariant safety firewall:
  joints, workspaces, authority chains, commands, and verdicts.
-/

namespace Invariant

-- ════════════════════════════════════════════════════════════════════
-- Joint domain
-- ════════════════════════════════════════════════════════════════════

/-- A joint definition from the robot profile. -/
structure JointDef where
  name : String
  min : Float
  max : Float
  maxVelocity : Float
  maxTorque : Float
  maxAcceleration : Float
  deriving Repr

/-- A commanded joint state. -/
structure JointState where
  name : String
  position : Float
  velocity : Float
  effort : Float
  deriving Repr

-- ════════════════════════════════════════════════════════════════════
-- Spatial domain
-- ════════════════════════════════════════════════════════════════════

/-- A point in 3D world frame. -/
structure Point3 where
  x : Float
  y : Float
  z : Float
  deriving Repr

/-- Axis-aligned bounding box. -/
structure AABB where
  min : Point3
  max : Point3
  deriving Repr

/-- Spherical zone with a velocity scaling factor. -/
structure ProximityZone where
  center : Point3
  radius : Float
  velocityScale : Float
  deriving Repr

/-- A named end-effector position. -/
structure EndEffectorPosition where
  name : String
  position : Point3
  deriving Repr

-- ════════════════════════════════════════════════════════════════════
-- Authority domain (PIC)
-- ════════════════════════════════════════════════════════════════════

/-- An operation string (e.g., "actuate:left_arm:*"). -/
abbrev Operation := String

/-- A single PCA hop in the authority chain. -/
structure PcaHop where
  p0 : String               -- origin principal (immutable)
  ops : List Operation       -- granted operations at this hop
  kid : String               -- key identifier of the signer
  signatureValid : Bool      -- whether Ed25519 signature verified
  deriving Repr

/-- A complete PCA authority chain. -/
structure AuthorityChain where
  hops : List PcaHop
  deriving Repr

-- ════════════════════════════════════════════════════════════════════
-- Command and verdict domain
-- ════════════════════════════════════════════════════════════════════

/-- Foot state for locomotion checks. -/
structure FootState where
  name : String
  position : Point3
  contact : Bool
  groundReactionForce : Option Point3
  deriving Repr

/-- Locomotion state carried in a command. -/
structure LocomotionState where
  baseVelocity : Point3
  headingRate : Float
  feet : List FootState
  stepLength : Float
  deriving Repr

/-- End-effector force reading. -/
structure EndEffectorForce where
  name : String
  force : Point3
  deriving Repr

/-- A motor command to be validated. -/
structure Command where
  sequence : Nat
  jointStates : List JointState
  deltaTime : Float
  endEffectorPositions : List EndEffectorPosition
  centerOfMass : Option Point3
  authority : AuthorityChain
  requiredOps : List Operation
  locomotionState : Option LocomotionState
  endEffectorForces : List EndEffectorForce
  estimatedPayloadKg : Option Float
  deriving Repr

/-- Robot profile against which commands are validated. -/
structure RobotProfile where
  joints : List JointDef
  workspace : AABB
  exclusionZones : List AABB
  proximityZones : List ProximityZone
  collisionPairs : List (String × String)
  minCollisionDistance : Float
  globalVelocityScale : Float
  maxDeltaTime : Float
  stabilityPolygon : Option (List (Float × Float))
  locomotionMaxVelocity : Option Float
  locomotionMaxStepLength : Option Float
  locomotionMinFootClearance : Option Float
  locomotionMaxGrf : Option Float
  locomotionFrictionCoeff : Option Float
  locomotionMaxHeadingRate : Option Float
  endEffectorMaxForce : Option Float
  endEffectorMaxGraspForce : Option Float
  endEffectorMinGraspForce : Option Float
  endEffectorMaxForceRate : Option Float
  endEffectorMaxPayloadKg : Option Float
  deriving Repr

/-- Result of a single check. -/
inductive CheckResult where
  | pass (name : String)
  | fail (name : String) (reason : String)
  deriving Repr

/-- Overall verdict: approved iff all checks pass. -/
structure Verdict where
  approved : Bool
  checks : List CheckResult
  deriving Repr

end Invariant
