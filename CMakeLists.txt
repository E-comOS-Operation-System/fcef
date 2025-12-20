cmake_minimum_required(VERSION 3.10)
project(FCEF LANGUAGES C)

# 设置C标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# 输出目录
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# 包含目录
include_directories(${CMAKE_SOURCE_DIR}/include)

# 库
add_library(fcef STATIC
    src/lib/fcef.c
    src/format/fcef_reader.c
    src/format/fcef_writer.c
    src/format/fcef_validator.c
)

# 工具
add_executable(fcef-dump src/tools/fcef-dump.c)
target_link_libraries(fcef-dump fcef)

# 如果有测试文件，创建可执行文件
if(EXISTS ${CMAKE_SOURCE_DIR}/tests/unit/test_basic.c)
    add_executable(test_basic tests/unit/test_basic.c)
    target_link_libraries(test_basic fcef)
endif()

# 安装
install(TARGETS fcef
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(TARGETS fcef-dump
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)
