cmake_minimum_required(VERSION 3.24)
project(provekit_v1_barretenberg_mobile LANGUAGES C CXX)

if(NOT DEFINED BB_V087_CPP_SOURCE)
  message(FATAL_ERROR "BB_V087_CPP_SOURCE must point to pinned v0.87.0 barretenberg/cpp")
endif()

set(DISABLE_AZTEC_VM ON CACHE BOOL "" FORCE)
set(DISABLE_ASM ON CACHE BOOL "" FORCE)
set(DISABLE_ADX ON CACHE BOOL "" FORCE)
set(MULTITHREADING OFF CACHE BOOL "" FORCE)
set(OMP_MULTITHREADING OFF CACHE BOOL "" FORCE)
set(TESTING OFF CACHE BOOL "" FORCE)
set(BENCHMARK OFF CACHE BOOL "" FORCE)
set(FUZZING OFF CACHE BOOL "" FORCE)
# Upstream's ENABLE_PIC also unconditionally builds its Node addon. Mobile
# needs PIC objects, not Node-API, so use CMake's standard setting directly.
set(ENABLE_PIC OFF CACHE BOOL "" FORCE)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
  # Xcode 26 diagnoses syntax accepted by the Clang generation used for v0.87.
  # This compatibility flag changes no source or proof-system behavior.
  add_compile_options(-Wno-missing-template-arg-list-after-template-kw)
  include_directories(BEFORE "${CMAKE_CURRENT_SOURCE_DIR}/compat/apple")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "iOS" OR ANDROID)
  # v0.87's CLI-oriented file loader shells out to `gunzip`, which is absent
  # from app sandboxes. Shadow only that header for mobile and decompress the
  # immutable .gz fixtures in-process through the platform zlib.
  include_directories(BEFORE "${CMAKE_CURRENT_SOURCE_DIR}/compat/mobile")
endif()

add_subdirectory("${BB_V087_CPP_SOURCE}" upstream EXCLUDE_FROM_ALL)

add_library(barretenberg_v087_mobile STATIC cpp/bb_v087_mobile.cpp)
target_include_directories(
  barretenberg_v087_mobile
  PUBLIC include
  PRIVATE
    "${BB_V087_CPP_SOURCE}/src"
    "${CMAKE_BINARY_DIR}/_deps/tracy-src/public"
    "${CMAKE_BINARY_DIR}/_deps/msgpack-c/src/msgpack-c/include"
    "${CMAKE_BINARY_DIR}/_deps/libdeflate-src"
)
target_compile_features(barretenberg_v087_mobile PRIVATE cxx_std_20)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  target_compile_options(
    barretenberg_v087_mobile PRIVATE
    -fbracket-depth=512
    -fconstexpr-steps=100000000
  )
endif()
target_link_libraries(barretenberg_v087_mobile PRIVATE barretenberg)
if(CMAKE_SYSTEM_NAME STREQUAL "iOS" OR ANDROID)
  target_link_libraries(barretenberg_v087_mobile PRIVATE z)
endif()
set_target_properties(
  barretenberg_v087_mobile
  PROPERTIES
    OUTPUT_NAME barretenberg_v087_mobile
    POSITION_INDEPENDENT_CODE ON
)

install(
  TARGETS barretenberg_v087_mobile barretenberg
  ARCHIVE DESTINATION lib
)
install(FILES include/bb_v087_mobile.h DESTINATION include)
