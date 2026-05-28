cmake_minimum_required(VERSION 3.20)
project(ThreefishEAX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# Use the local modified cryptopp source (avx512 branch) instead of upstream.
# This contains modified threefish.h/cpp with AVX-512 dispatch support.
set(CRYPTOPP_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/../cryptopp" CACHE PATH "" FORCE)

# Disable intermediate object target so compile definitions propagate correctly.
set(CRYPTOPP_USE_INTERMEDIATE_OBJECTS_TARGET OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
  cryptopp-cmake
  GIT_REPOSITORY https://github.com/abdes/cryptopp-cmake.git
  GIT_TAG        master
)

set(CRYPTOPP_BUILD_TESTING OFF CACHE BOOL "Build Crypto++ tests" FORCE)

FetchContent_MakeAvailable(cryptopp-cmake)

# Enable AVX-512 Threefish-1024 dispatch in the cryptopp library and all consumers.
# PUBLIC ensures ABI consistency between library and CLI (the macro changes class layout).
target_compile_definitions(cryptopp PUBLIC CRYPTOPP_THREEFISH1024_AVX512_AVAILABLE)

# Add the AVX-512 implementation file to the cryptopp target.
# The file uses #pragma GCC target("avx512f") internally, so no extra flags needed.
target_sources(cryptopp PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../cryptopp/threefish1024_avx512_cryptopp.cpp")

add_executable(Threefish1024-eax main.cpp)
target_link_libraries(Threefish1024-eax PRIVATE cryptopp::cryptopp)
