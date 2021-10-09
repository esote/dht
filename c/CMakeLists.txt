cmake_minimum_required(VERSION 3.20)

project(dhtd
	VERSION 0.0.1
	DESCRIPTION "distributed hash table daemon"
	LANGUAGES C)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O2 -Wall -D C1=2 -D C2=2")

add_subdirectory(src)
enable_testing()
add_subdirectory(test)
