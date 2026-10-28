cmake_minimum_required(VERSION 3.20)
project(RustCloak LANGUAGES CXX)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Building RustCloak against LLVM ${LLVM_PACKAGE_VERSION}")

list(APPEND CMAKE_MODULE_PATH ${LLVM_CMAKE_DIR})
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND "${LLVM_DEFINITIONS}")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(RustCloak MODULE
  src/Flatten.cpp
  src/StrEnc.cpp
  src/Subst.cpp
  src/Bogus.cpp
  src/Virt.cpp
  src/ConstEnc.cpp
  src/AntiTamper.cpp
  src/License.cpp
  src/ImportHide.cpp
  src/Plugin.cpp)
target_include_directories(RustCloak PRIVATE src)
# LLVM is normally built without RTTI; match it or the plugin fails to load.
target_compile_options(RustCloak PRIVATE -fno-rtti -Wall)
set_target_properties(RustCloak PROPERTIES PREFIX "lib")
