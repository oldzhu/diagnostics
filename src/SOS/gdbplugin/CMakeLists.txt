project(sosgdbplugin)

if(CLR_CMAKE_HOST_UNIX)
  add_subdirectory(gdbbridge)
endif()
