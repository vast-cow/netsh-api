cmake_minimum_required(VERSION 3.20)

project(network_rules LANGUAGES CXX)

if (NOT WIN32)
    message(FATAL_ERROR "This example is Windows-only")
endif()

add_executable(network_rules
    main.cpp
    WindowsNetworkConfig.cpp
    WindowsNetworkConfig.h
)

target_compile_features(network_rules PRIVATE cxx_std_17)
target_compile_definitions(network_rules PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
target_link_libraries(network_rules PRIVATE advapi32 ole32 oleaut32 ws2_32)

if (MSVC)
    target_compile_options(network_rules PRIVATE /W4 /EHsc)
endif()
