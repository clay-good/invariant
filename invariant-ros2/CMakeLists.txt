cmake_minimum_required(VERSION 3.8)
project(invariant_ros2)

find_package(ament_cmake REQUIRED)
find_package(rosidl_default_generators REQUIRED)
find_package(builtin_interfaces REQUIRED)
find_package(std_msgs REQUIRED)

# Generate message types from .msg files.
rosidl_generate_interfaces(${PROJECT_NAME}
  "msg/JointState.msg"
  "msg/EndEffectorPosition.msg"
  "msg/CommandAuthority.msg"
  "msg/CheckResult.msg"
  "msg/AuthoritySummary.msg"
  "msg/Command.msg"
  "msg/SignedVerdict.msg"
  "msg/SignedActuation.msg"
  DEPENDENCIES builtin_interfaces
)

# Install the Python bridge node.
install(
  DIRECTORY invariant_ros2/
  DESTINATION lib/python3/dist-packages/invariant_ros2
)

# Install launch files.
install(
  DIRECTORY launch/
  DESTINATION share/${PROJECT_NAME}/launch
)

ament_package()
