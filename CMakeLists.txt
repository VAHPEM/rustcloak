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

# RustCloak ships in two tiers:
#   CORE     (src/)     Apache-2.0        flatten, strenc, subst, bogus, constenc
#   PREMIUM  (premium/)  AGPL-or-commercial  virt (code virtualization), antitamper, license, imphide
# Premium is built in by default. Configure with -DRUSTCLOAK_PREMIUM=OFF for a core-only,
# Apache-2.0 plugin (no VM / anti-tamper / license gate / import hiding).
option(RUSTCLOAK_PREMIUM "Build the AGPL-or-commercial premium tier (premium/)" ON)

set(RUSTCLOAK_SOURCES
  src/Flatten.cpp
  src/StrEnc.cpp
  src/Subst.cpp
  src/Bogus.cpp
  src/ConstEnc.cpp
  src/Plugin.cpp)

if(RUSTCLOAK_PREMIUM)
  list(APPEND RUSTCLOAK_SOURCES
    premium/Virt.cpp
    premium/AntiTamper.cpp
    premium/License.cpp
    premium/ImportHide.cpp)
  message(STATUS "RustCloak: premium tier ENABLED (virt, antitamper, license, imphide)")
else()
  message(STATUS "RustCloak: premium tier DISABLED -- core only (Apache-2.0)")
endif()

add_library(RustCloak MODULE ${RUSTCLOAK_SOURCES})
target_include_directories(RustCloak PRIVATE src premium)
if(RUSTCLOAK_PREMIUM)
  target_compile_definitions(RustCloak PRIVATE RUSTCLOAK_PREMIUM)
endif()
# LLVM is normally built without RTTI; match it or the plugin fails to load.
target_compile_options(RustCloak PRIVATE -fno-rtti -Wall)
set_target_properties(RustCloak PROPERTIES PREFIX "lib")
