set(CMAKE_SYSTEM_NAME Windows)

SET(CMAKE_C_COMPILER /opt/msvc/bin/x64/cl)
SET(CMAKE_CXX_COMPILER /opt/msvc/bin/x64/cl)
SET(CMAKE_RC_COMPILER /opt/msvc/bin/x64/rc)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MANIFEST:NO")
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} /MANIFEST:NO")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /MANIFEST:NO")
