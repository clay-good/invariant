"""Launch file for the Invariant ROS 2 bridge node.

Usage:
    ros2 launch invariant_ros2 invariant.launch.py
    ros2 launch invariant_ros2 invariant.launch.py socket_path:=/tmp/custom.sock
"""

from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument
from launch.substitutions import LaunchConfiguration
from launch_ros.actions import Node


def generate_launch_description():
    return LaunchDescription([
        DeclareLaunchArgument(
            "socket_path",
            default_value="/tmp/invariant.sock",
            description="Path to the Invariant Unix domain socket.",
        ),
        DeclareLaunchArgument(
            "heartbeat_forward",
            default_value="true",
            description="Forward /invariant/heartbeat to the Invariant binary.",
        ),
        Node(
            package="invariant_ros2",
            executable="invariant_node",
            name="invariant_node",
            parameters=[{
                "socket_path": LaunchConfiguration("socket_path"),
                "heartbeat_forward": LaunchConfiguration("heartbeat_forward"),
            }],
            output="screen",
        ),
    ])
