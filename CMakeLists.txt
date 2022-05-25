cmake_minimum_required(VERSION 3.10)

project(ssisdump)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

set(SRC_FILES
	src/ssisdump.cpp
	src/aes.cpp)

add_executable(ssisdump ${SRC_FILES})

find_package(tdscpp REQUIRED)

target_link_libraries(ssisdump tdscpp)

if(NOT MSVC)
	target_compile_options(ssisdump PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion)
else()
	target_link_options(ssisdump PUBLIC /MANIFEST:NO)
endif()
