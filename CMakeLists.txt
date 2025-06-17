cmake_minimum_required(VERSION 3.29)
project(packetSnifferJNI)

set(CMAKE_CXX_STANDARD 20)

include_directories(
        "C:/Program Files/Java/jdk-17/include"
        "C:/Program Files/Java/jdk-17/include/win32"
)

add_executable(packetSnifferJNI main.cpp
        packet_capture_kernal_mode.cpp
        ProcessUtils.cpp
        PacketDriverBridge.cpp
        Launcher.cpp)

target_link_options(packetSnifferJNI PRIVATE "/MANIFEST:EMBED" "/MANIFESTINPUT:additionalFiles/Launcher.manifest")
