# ROS 2 Bridge

The `invariant-ros2/` ament/colcon package wraps the Invariant validator
as a ROS 2 node. It is intentionally a thin transport — every validation
decision happens in the Rust binary; the Python node only translates ROS
2 messages to and from the Unix-socket bridge.

Cross-references: [invariant-ros2/package.xml](../invariant-ros2/package.xml),
[crates/invariant-sim/src/robotics/isaac/bridge.rs](../crates/invariant-sim/src/robotics/isaac/bridge.rs)
(the matching server side), `docs/robotics/spec.md` §21.3.

## Status (v11-5.11 disposition: **Keep**)

The ROS 2 bridge is kept in tree but **deliberately outside the Cargo
workspace** — it has no Rust code and would only slow `cargo build`. It is
also outside CI today (no `colcon` runner available); contributors who
modify it must verify locally with the build steps below, and the next
release that lands a ROS 2 CI runner should add a `colcon build` smoke
job.

Removal was considered (Option B in the v11 prompt) and rejected:

- The `.msg` files are the public ROS 2 contract for downstream
  integrators. Deleting them would break any external `ament` workspace
  that depends on `invariant_ros2`.
- The Python node is small (~1 file) and stable; maintenance cost is
  near zero.
- The Unix-socket protocol on the Rust side ([bridge.rs](../crates/invariant-sim/src/robotics/isaac/bridge.rs))
  is shared with the Isaac Lab bridge, so the ROS 2 transport rides on
  hardening already done for Isaac.

If a future audit finds the package is bit-rotting or unused,
re-evaluate against [Option B](#removal-runbook).

## Layout

```
invariant-ros2/
├── package.xml                              # ament manifest
├── CMakeLists.txt                           # ament_cmake build rules
├── msg/                                     # IDL: 8 .msg files
│   ├── Command.msg
│   ├── CommandAuthority.msg
│   ├── JointState.msg
│   ├── EndEffectorPosition.msg
│   ├── CheckResult.msg
│   ├── AuthoritySummary.msg
│   ├── SignedVerdict.msg
│   └── SignedActuation.msg
├── invariant_ros2/
│   ├── __init__.py
│   └── invariant_node.py                    # the bridge node
├── launch/
│   └── invariant.launch.py
└── test/
    └── test_conversion.py                   # JSON ↔ ROS 2 message round-trip
```

## Build locally

Prereqs: ROS 2 Humble (or later) on Ubuntu 22.04+; the Invariant Rust
binary built and on `$PATH`.

```sh
# 1. Source ROS 2.
source /opt/ros/humble/setup.bash

# 2. Build the package inside a colcon workspace.
mkdir -p ~/invariant_ws/src
ln -s "$(pwd)/invariant-ros2" ~/invariant_ws/src/invariant_ros2
cd ~/invariant_ws
colcon build --packages-select invariant_ros2

# 3. Source the overlay and run the node.
source install/setup.bash
ros2 run invariant_ros2 invariant_node --ros-args \
    -p socket_path:=/tmp/invariant.sock
```

In a second terminal, start the Rust bridge server:

```sh
invariant robotics serve --bridge-socket /tmp/invariant.sock \
    --profile profiles/robotics/ur10e_haas_cell.json \
    --key keys.json
```

The node subscribes to `/invariant/command`, forwards each message over
the Unix socket, and publishes `/invariant/verdict` (and
`/invariant/actuation` for approved commands).

## Topics

| Direction | Topic                    | Type                      | Notes |
|-----------|--------------------------|---------------------------|-------|
| sub       | `/invariant/command`     | `invariant_ros2/Command`  | One command per inbound message. |
| sub       | `/invariant/heartbeat`   | `std_msgs/Empty`          | Resets the watchdog window on the Rust side. |
| pub       | `/invariant/verdict`     | `invariant_ros2/SignedVerdict` | Always published, approved or not. |
| pub       | `/invariant/actuation`   | `invariant_ros2/SignedActuation` | Approved-only. |
| pub       | `/invariant/status`      | `std_msgs/String`         | Node health snapshot, every second. |

## CI smoke test (deferred)

Adding `colcon build` to CI requires a ROS 2 runner image, which the
project does not currently maintain. Two acceptable paths:

1. **Docker matrix job** — add a GitHub Actions matrix entry running on
   `osrf/ros:humble-desktop`. Invokes `colcon build --packages-select
   invariant_ros2 && colcon test`. Estimated build time: ~3 min.
2. **Out-of-tree CI** — host the smoke build in a separate workflow file
   that runs weekly rather than per-PR (lower signal, lower cost).

Tracking: opening this is queued as a follow-up under v11 5.11; the
disposition is **Keep** without a per-PR CI gate.

## Removal runbook

If a future audit concludes the package should be deleted:

1. `git rm -r invariant-ros2/`
2. Update [`README.md`](../README.md) to drop the ROS 2 mention.
3. Add a `CHANGELOG.md` entry under "Removed":
   > Removed the `invariant-ros2/` ament package. Downstream integrators
   > should pin to the previous tag if they need the message
   > definitions.
4. Cross-link from [docs/robotics/spec.md](robotics/spec.md) §21.3 to
   the removal commit SHA so the design history is preserved.
