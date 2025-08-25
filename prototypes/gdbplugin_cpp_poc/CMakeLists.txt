cmake_minimum_required(VERSION 3.13)

project(gdbplugin)

add_library(gdbplugin MODULE
    gdbplugin.cpp
    services.cpp
    gdbcommand.cpp
)

target_include_directories(gdbplugin PRIVATE
    ../inc
    # Add the GDB header path.
    /usr/include/gdb
)

target_link_libraries(gdbplugin PRIVATE
    dl
)

set_target_properties(gdbplugin PROPERTIES
    PREFIX ""
    OUTPUT_NAME "gdbplugin.so"
)

install(TARGETS gdbplugin
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/
)