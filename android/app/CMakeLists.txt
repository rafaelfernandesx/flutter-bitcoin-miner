cmake_minimum_required(VERSION 3.4.1)  # for example

add_library( miner_lib
    # Sets the library as a shared library.
    SHARED
    # Provides a relative path to your source file(s).
    miner_cpp/miner.cpp
)