cmake_minimum_required(VERSION 3.11)
include(CheckPrototypeDefinition)

project("purelibc")

set(CMAKE_C_FLAGS
    "-ggdb -Wall -Wextra -pedantic -std=gnu11 -Wno-incompatible-pointer-types -Wno-unused-parameter")
find_library(LIBDL dl)

add_definitions(-D_GNU_SOURCE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
set(HEADERS purelibc.h)

check_prototype_definition(gettimeofday
	"int gettimeofday(struct timeval *tv, struct timezone *tz)"
	"0"
	"sys/time.h"
	GETTIMEOFDAY_TZ)

check_prototype_definition(gettimeofday
	"int gettimeofday(struct timeval *tv, void *tz)"
	"0"
	"sys/time.h"
	GETTIMEOFDAY_VOID)

if(${GETTIMEOFDAY_TZ})
 	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DGETTIMEOFDAY_TZ")
endif()

add_library(purelibc SHARED
		dir.c  exec.c  socketcalls.c  stdio.c  syscalls.c
)
target_link_libraries(purelibc ${LIBDL})

set_target_properties(purelibc PROPERTIES 
		VERSION "1.0.2"
		SOVERSION "1")

install(TARGETS purelibc LIBRARY DESTINATION lib)
install(FILES ${HEADERS} DESTINATION include)

