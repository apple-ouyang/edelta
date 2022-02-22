cmake_minimum_required(VERSION 3.11.0)

# GoogleTest requires at least C++11
set(CMAKE_CXX_STANDARD 11)

add_executable(encode-decode-test encode-decode-test.cc)

target_link_libraries(encode-decode-test edelta boost_filesystem boost_system gtest gtest_main pthread)