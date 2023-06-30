cmake_minimum_required(VERSION 3.30)
project(ThreefishEAX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(
  cryptopp-cmake
  GIT_REPOSITORY https://github.com/abdes/cryptopp-cmake.git
  GIT_TAG        master
)

#set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries" FORCE)
set(CRYPTOPP_BUILD_TESTING OFF CACHE BOOL "Build Crypto++ tests" FORCE)
#set(CRYPTOPP_INSTALL OFF CACHE BOOL "Install Crypto++" FORCE)

FetchContent_MakeAvailable(cryptopp-cmake)

add_executable(Threefish1024-eax main.cpp)

target_link_libraries(Threefish1024-eax PRIVATE cryptopp::cryptopp)
