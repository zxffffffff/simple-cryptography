#############################################################################
## MIT License
## 
## Author	: xiaofeng.zhu
## Support	: zxffffffff@outlook.com, 1337328542@qq.com
## 
#############################################################################

project(simple-cryptography-lib)
message("[${PROJECT_NAME}] -------- start")

message(STATUS "[${PROJECT_NAME}] PROJECT_SOURCE_DIR : ${PROJECT_SOURCE_DIR}")

# 引入 fmt
find_package(fmt CONFIG REQUIRED)

# 引入 boost (大部分 header-only 的库不需要 link)
find_package(Boost REQUIRED)
message(STATUS "[${PROJECT_NAME}] Boost_VERSION_STRING : ${Boost_VERSION_STRING}")
message(STATUS "[${PROJECT_NAME}] Boost_INCLUDE_DIRS : ${Boost_INCLUDE_DIRS}")
message(STATUS "[${PROJECT_NAME}] Boost_LIBRARY_DIRS : ${Boost_LIBRARY_DIRS}")
include_directories(${Boost_INCLUDE_DIRS})

# 引入 cryptopp
find_package(cryptopp CONFIG REQUIRED)

# 引入 zlib
find_package(ZLIB REQUIRED)
message(STATUS "[${PROJECT_NAME}] ZLIB_VERSION_STRING : ${ZLIB_VERSION_STRING}")
message(STATUS "[${PROJECT_NAME}] ZLIB_INCLUDE_DIRS : ${ZLIB_INCLUDE_DIRS}")
message(STATUS "[${PROJECT_NAME}] ZLIB_LIBRARIES : ${ZLIB_LIBRARIES}")

# 引入 snappy
find_package(Snappy CONFIG REQUIRED)

# Public 头文件
file(GLOB_RECURSE include_headers
    cpp_version.h
    cpp_def.h
    common.h
    chrono.h
)

add_library(${PROJECT_NAME} STATIC
    sample/sample_tools.cpp # needed
    ${include_headers}
)

target_link_libraries(${PROJECT_NAME}
    PUBLIC fmt::fmt-header-only
    PUBLIC cryptopp::cryptopp
    PUBLIC ZLIB::ZLIB
    PUBLIC Snappy::snappy
)

target_include_directories(${PROJECT_NAME}
    PUBLIC ${PROJECT_SOURCE_DIR}
)

set_target_properties(${PROJECT_NAME}
    PROPERTIES
    PUBLIC_HEADER "${include_headers}"
)

install(TARGETS ${PROJECT_NAME}
    PUBLIC_HEADER DESTINATION include
    RUNTIME DESTINATION bin # .dll
    LIBRARY DESTINATION bin # .dylib .so
    ARCHIVE DESTINATION lib # .lib .a
)

message("[${PROJECT_NAME}] -------- done")
