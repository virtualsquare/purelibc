cmake_minimum_required(VERSION 2.6)
project("purelibc")

set(CMAKE_C_FLAGS
    "-ggdb -Wall -Wextra -pedantic -std=gnu11 -Wno-incompatible-pointer-types -Wno-unused-parameter")
find_library(LIBDL dl)

add_definitions(-D_GNU_SOURCE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
set(HEADERS purelibc.h)

add_library(purelibc SHARED
		dir.c  exec.c  socketcalls.c  stdio.c  syscalls.c
)
target_link_libraries(purelibc ${LIBDL})

set_target_properties(purelibc PROPERTIES 
		VERSION "1.0.2"
		SOVERSION "1")

install(TARGETS purelibc LIBRARY DESTINATION lib)
install(FILES ${HEADERS} DESTINATION include)

