# Copyright (c) 2023 Microsoft Corporation.
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.16)
project("dns_watcher")

include("cmake/platform.cmake")
include("cmake/options.cmake")
include("cmake/version.cmake")


if (PLATFORM_WINDOWS)
  find_program(NUGET nuget)
  if(NOT NUGET)
    message("ERROR: You must first install nuget.exe from https://www.nuget.org/downloads")
  else()
    # if BPF_PERF_LOCAL_NUGET_PATH is set, use that as the source for the eBPF-for-Windows package
    if(BPF_PERF_LOCAL_NUGET_PATH)
      exec_program(${NUGET} ARGS install "eBPF-for-Windows" -ExcludeVersion -OutputDirectory ${PROJECT_BINARY_DIR}/packages -Source ${BPF_PERF_LOCAL_NUGET_PATH} -NoCache)
    else()
      exec_program(${NUGET} ARGS install "eBPF-for-Windows" -Version 0.18.0 -ExcludeVersion -OutputDirectory ${PROJECT_BINARY_DIR}/packages)
    endif()
  endif()
  set(EBPF_LIB "ebpfapi")
  set(EBPF_INC_PATH "${PROJECT_BINARY_DIR}/packages/eBPF-for-Windows/build/native/include")
  set(EBPF_LIB_PATH "${PROJECT_BINARY_DIR}/packages/eBPF-for-Windows/build/native/lib")
  set(EBPF_BIN_PATH "${PROJECT_BINARY_DIR}/packages/eBPF-for-Windows/build/native/bin")

  # Download the XDP-dev-kit from GitHub
  file(READ "${CMAKE_SOURCE_DIR}/scripts/xdp_version.txt" XDP_VERSION)
  file(DOWNLOAD "${XDP_VERSION}/xdp-devkit-x64-1.1.0.zip" "${PROJECT_BINARY_DIR}/packages/xdp-devkit.zip")
  # Unzip the XDP-dev-kit
  # Create folder xdp-devkit
  file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/packages/xdp-devkit")
  # Unzip the xdp-devkit.zip file into the xdp-devkit folder
  execute_process(COMMAND ${CMAKE_COMMAND} -E tar xzf "${PROJECT_BINARY_DIR}/packages/xdp-devkit.zip" WORKING_DIRECTORY "${PROJECT_BINARY_DIR}/packages/xdp-devkit")

  SET(XDP_INC_PATH "${PROJECT_BINARY_DIR}/packages/xdp-devkit/include")
  SET(XDP_LIB_PATH "${PROJECT_BINARY_DIR}/packages/xdp-devkit/lib")
  SET(XDP_BIN_PATH "${PROJECT_BINARY_DIR}/packages/xdp-devkit/bin")
  # Run xdp_bpfexport.exe from the xdp-dev-kit
  execute_process(COMMAND "${PROJECT_BINARY_DIR}/packages/xdp-devkit/bin/xdp_bpfexport.exe" WORKING_DIRECTORY "${EBPF_BIN_PATH}")

elseif(PLATFORM_LINUX)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(LIBBPF REQUIRED libbpf)
  set(EBPF_LIB ${LIBBPF_LIBRARIES})
  set(EBPF_INC_PATH ${LIBBPF_INCLUDEDIR})
  set(EBPF_LIB_PATH ${LIBBPF_LIBDIR})
  # Print out the libbpf version
  message(STATUS "libbpf version: ${LIBBPF_VERSION}")
  message(STATUS "libbpf include dirs: ${LIBBPF_INCLUDEDIR}")
  message(STATUS "libbpf library dirs: ${LIBBPF_LIBDIR}")
  message(STATUS "libbpf libraries: ${LIBBPF_LIBRARIES}")

endif()

if(PLATFORM_WINDOWS)
message("Setting CONTROL FLOW GUARD")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /guard:cf")
SET(CMAKE_EXE_LINKER_FLAGS  "/guard:cf /DYNAMICBASE")

message("Setting QSPECTRE")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Qspectre")
endif()

add_subdirectory(watcher)
add_subdirectory(bpf)

