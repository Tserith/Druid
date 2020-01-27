cmake_minimum_required(VERSION 3.1)
project(Druid)
set(CMAKE_BUILD_TYPE Release)
include_directories(include)

add_executable(stub src/stub.c src/chacha20.c)
add_executable(druid src/packer.c src/chacha20.c)

# necessary, resources not supported
set(STUB_LINK_FLAGS "/MANIFEST:NO")

# not required, but used to make stub look nicer
set_target_properties(stub PROPERTIES LINK_FLAGS "${STUB_LINK_FLAGS} /EMITPOGOPHASEINFO /ENTRY:main")
set_target_properties(stub PROPERTIES COMPILE_FLAGS "/GS-")

target_link_libraries(druid "Imagehlp.dll")

if(MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()