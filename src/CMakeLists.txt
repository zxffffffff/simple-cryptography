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

# 引入 openssl
find_package(OpenSSL REQUIRED)

# 引入 cryptopp
find_package(cryptopp CONFIG REQUIRED)

# 引入 zlib
find_package(ZLIB REQUIRED)
message(STATUS "[${PROJECT_NAME}] ZLIB_VERSION_STRING : ${ZLIB_VERSION_STRING}")
message(STATUS "[${PROJECT_NAME}] ZLIB_INCLUDE_DIRS : ${ZLIB_INCLUDE_DIRS}")
message(STATUS "[${PROJECT_NAME}] ZLIB_LIBRARIES : ${ZLIB_LIBRARIES}")

# 引入 snappy
find_package(Snappy CONFIG REQUIRED)

# 引入 secp256k1
FetchContent_Declare(
    secp256k1
    GIT_REPOSITORY https://github.com/zxffffffff/secp256k1.git
    GIT_TAG master
)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries" FORCE)
FetchContent_MakeAvailable(secp256k1)
unset(BUILD_SHARED_LIBS CACHE)
message(STATUS "[${PROJECT_NAME}] secp256k1_SOURCE_DIR : ${secp256k1_SOURCE_DIR}")

# 引入 sss
FetchContent_Declare(
    sss
    GIT_REPOSITORY https://github.com/zxffffffff/sss.git
    GIT_TAG master
)
FetchContent_MakeAvailable(sss)
message(STATUS "[${PROJECT_NAME}] sss_SOURCE_DIR : ${sss_SOURCE_DIR}")

# 引入 liboqs (依赖 doxygen)
FetchContent_Declare(
    oqs
    GIT_REPOSITORY https://github.com/zxffffffff/liboqs.git
    GIT_TAG main
)
FetchContent_MakeAvailable(oqs)
message(STATUS "[${PROJECT_NAME}] oqs_SOURCE_DIR : ${oqs_SOURCE_DIR}")
set(oqs_BUILD_DIR "${oqs_SOURCE_DIR}/../oqs-build")
set(oqs_INCLUDE_DIR "${oqs_BUILD_DIR}/include")

# Public 头文件
file(GLOB_RECURSE include_headers
    common/cpp_version.h
    common/cpp_def.h
    common/common.h
    common/chrono.h
    StringBuffer.h
    Cryptography.h
    SecurityBuffer.h
)

add_library(${PROJECT_NAME} STATIC
    Cryptography-hash-openssl.cpp
    Cryptography-aes-openssl.cpp
    Cryptography-rsa-openssl.cpp
    Cryptography-ecc-secp256k1.cpp
    Cryptography-sss.cpp
    Cryptography-kyber-liboqs.cpp
    ${include_headers}
)

target_link_libraries(${PROJECT_NAME}
    PUBLIC fmt::fmt-header-only
    PUBLIC OpenSSL::SSL
    PUBLIC OpenSSL::Crypto
    PUBLIC cryptopp::cryptopp
    PUBLIC ZLIB::ZLIB
    PUBLIC Snappy::snappy
    PUBLIC secp256k1
    PUBLIC sss
    PUBLIC oqs
)

target_include_directories(${PROJECT_NAME}
    PUBLIC ${PROJECT_SOURCE_DIR}
    PUBLIC ${secp256k1_SOURCE_DIR}
    PUBLIC ${sss_SOURCE_DIR}
    PUBLIC ${oqs_INCLUDE_DIR}
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
