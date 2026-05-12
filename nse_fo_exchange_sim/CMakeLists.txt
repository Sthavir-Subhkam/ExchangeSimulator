cmake_minimum_required(VERSION 3.16)

project(nse_fo_exchange_sim LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_library(nse_fo_exchange_sim_lib
  src/config.cpp
  src/crypto.cpp
  src/simulator.cpp
)

target_include_directories(nse_fo_exchange_sim_lib
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(nse_fo_exchange_sim_lib
  PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

target_compile_options(nse_fo_exchange_sim_lib
  PRIVATE
    -Wall
    -Wextra
    -Wno-deprecated-declarations
)

add_executable(nse_fo_exchange_sim
  src/main.cpp
)

target_link_libraries(nse_fo_exchange_sim
  PRIVATE
    nse_fo_exchange_sim_lib
)

enable_testing()

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/testdata/tls)
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/testdata/tls/server.crt
  ${CMAKE_CURRENT_BINARY_DIR}/testdata/tls/server.crt
  COPYONLY
)
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/testdata/tls/server.key
  ${CMAKE_CURRENT_BINARY_DIR}/testdata/tls/server.key
  COPYONLY
)

add_executable(nse_fo_exchange_sim_tests
  tests/test_main.cpp
)

target_link_libraries(nse_fo_exchange_sim_tests
  PRIVATE
    nse_fo_exchange_sim_lib
)

add_test(
  NAME nse_fo_exchange_sim_tests
  COMMAND nse_fo_exchange_sim_tests
)
