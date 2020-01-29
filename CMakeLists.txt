cmake_minimum_required(VERSION 3.1)
project(Druid)
set(CMAKE_BUILD_TYPE Release)
include_directories(include)

add_executable(stub src/stub.c src/chacha20.c)
add_executable(druid src/packer.c src/chacha20.c)

# necessary for stub - resources not supported
set(STUB_LINK_FLAGS "/MANIFEST:NO")

# optional to hide console window of packed executable
#set(STUB_LINK_FLAGS "${STUB_LINK_FLAGS} /SUBSYSTEM:WINDOWS")

# not required, but used to make the stub look nicer
set_target_properties(stub PROPERTIES LINK_FLAGS "${STUB_LINK_FLAGS} /EMITPOGOPHASEINFO /ENTRY:WinMain")
set_target_properties(stub PROPERTIES COMPILE_FLAGS "/GS-")

target_link_libraries(druid "Imagehlp.dll")

if(MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()