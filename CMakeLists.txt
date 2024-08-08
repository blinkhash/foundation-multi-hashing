cmake_minimum_required(VERSION 3.5.1)
project(multihashing)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

file(GLOB multihashing_SRC
        "src/*/*.c"
        "src/*.c"
        "src/*.cpp"
        "src/*/*.cpp"
        )

#ff building Node JS Addon
if (CMAKE_JS_VERSION)

    set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++ -static")
    set(secp256k1_libs)

    # add node include directories, fix potential backslashes
    foreach(CMAKE_JS_INC_ITEM ${CMAKE_JS_INC})
        string(REPLACE "\\" "/" CMAKE_JS_INC_ITEM ${CMAKE_JS_INC_ITEM})
        message(STATUS "include_directories ${CMAKE_JS_INC_ITEM}")
        include_directories(${CMAKE_JS_INC_ITEM})
    endforeach(CMAKE_JS_INC_ITEM)

    string(REPLACE "\\" "/" PROJECT_SOURCE_DIR ${PROJECT_SOURCE_DIR})
    message(STATUS "include_directories ${PROJECT_SOURCE_DIR}")
    include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR})
    include_directories(${PROJECT_NAME} PUBLIC "./src")

    # include static libraries
    include(ProjectSecp256k1)

    add_library(${PROJECT_NAME} SHARED ${multihashing_SRC} "multihashing.cc")
    set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")

endif()
