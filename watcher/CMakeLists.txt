# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_REQUIRED_INCLUDES ${EBPF_INC_PATH})

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)

add_executable(
  dns_watcher
  watcher.cc
  watcher.h
)

target_include_directories(dns_watcher PRIVATE ${EBPF_INC_PATH})
target_link_directories(dns_watcher PRIVATE ${EBPF_LIB_PATH})
target_link_libraries(dns_watcher PRIVATE ${EBPF_LIB})
