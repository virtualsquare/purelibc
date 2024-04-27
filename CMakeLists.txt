cmake_minimum_required(VERSION 3.13)
project(purelibc
 VERSION 1.0.8
 DESCRIPTION "A glibc overlay library for process self-virtualization."
 HOMEPAGE_URL "https://github.com/virtualsquare/purelibc"
 LANGUAGES C)
include(GNUInstallDirs)

include(CheckPrototypeDefinition)

set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -O2 -D_FORTIFY_SOURCE=2 -ggdb -Wall -Wextra -pedantic -std=gnu11 -Wno-incompatible-pointer-types -Wno-unused-parameter")
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

set_target_properties(purelibc PROPERTIES VERSION ${PROJECT_VERSION}
	SOVERSION ${PROJECT_VERSION_MAJOR})

install(TARGETS purelibc LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

add_custom_target(uninstall
	"${CMAKE_COMMAND}" -P "${PROJECT_SOURCE_DIR}/Uninstall.cmake")
