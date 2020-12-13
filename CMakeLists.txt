cmake_minimum_required(VERSION 3.1)
project(Druid)
set(CMAKE_BUILD_TYPE Release)
include_directories(include)

add_executable(stub src/stub.c src/chacha20.c)
add_library(stub_dll SHARED src/stub.c src/chacha20.c)
add_executable(druid src/cryptor.c src/chacha20.c)

# necessary for stub - resources not supported
set(STUB_LINK_FLAGS "/MANIFEST:NO")

# optional to hide console window of encrypted executable
#set(STUB_LINK_FLAGS "${STUB_LINK_FLAGS} /SUBSYSTEM:WINDOWS")

# not required, but used to make the stub look nicer
set_target_properties(stub PROPERTIES LINK_FLAGS "${STUB_LINK_FLAGS} /EMITPOGOPHASEINFO /ENTRY:WinMain")
set_target_properties(stub PROPERTIES COMPILE_FLAGS "/GS-")
set_target_properties(stub_dll PROPERTIES LINK_FLAGS "${STUB_LINK_FLAGS} /EMITPOGOPHASEINFO /ENTRY:DllMain")
set_target_properties(stub_dll PROPERTIES OUTPUT_NAME "stub")
set_target_properties(stub_dll PROPERTIES SUFFIX ".dll")
set_target_properties(stub_dll PROPERTIES COMPILE_FLAGS "/GS- /DSTUB_DLL")

target_link_libraries(druid "Imagehlp.dll")

if(MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()