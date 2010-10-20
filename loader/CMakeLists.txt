project(himemce)
cmake_minimum_required(VERSION 2.6.0)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# For dlmalloc.h
add_definitions(-DUSE_DL_PREFIX=1)

add_library(libhimemce SHARED libhimemce.c libhimemce.def)
install(TARGETS libhimemce DESTINATION bin)

add_executable(himemce himemce.c
  wine.h my_winternl.h compat.c
#  dlmalloc.h dlmalloc.c
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c)
target_link_libraries(himemce libhimemce)
install(TARGETS himemce DESTINATION bin)

add_executable(kmail-mobile-loader himemce.c
  wine.h my_winternl.h compat.c
#  dlmalloc.h dlmalloc.c
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c kmail-mobile.rc)
target_link_libraries(kmail-mobile-loader libhimemce)
install(TARGETS kmail-mobile-loader DESTINATION bin)

add_executable(notes-mobile-loader himemce.c
  wine.h my_winternl.h compat.c
#  dlmalloc.h dlmalloc.c
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c notes-mobile.rc)
target_link_libraries(notes-mobile-loader libhimemce)
install(TARGETS notes-mobile-loader DESTINATION bin)

add_executable(kaddressbook-mobile-loader himemce.c
  wine.h my_winternl.h compat.c
#  dlmalloc.h dlmalloc.c
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c kaddressbook-mobile.rc)
target_link_libraries(kaddressbook-mobile-loader libhimemce)
install(TARGETS kaddressbook-mobile-loader DESTINATION bin)

add_executable(korganizer-mobile-loader himemce.c himemce.c
  wine.h my_winternl.h compat.c
#  dlmalloc.h dlmalloc.c
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c korganizer-mobile.rc)
target_link_libraries(korganizer-mobile-loader libhimemce)
install(TARGETS korganizer-mobile-loader DESTINATION bin)

add_executable(tasks-mobile-loader himemce.c
  wine.h my_winternl.h compat.c
#  dlmalloc.h dlmalloc.c
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c tasks-mobile.rc)
target_link_libraries(tasks-mobile-loader libhimemce)
install(TARGETS tasks-mobile-loader DESTINATION bin)
#Example rules how to build a library.
#add_library(newtest SHARED newtest.cpp newtest.def)
#add_executable(newtestex newtestex.cpp)
#target_link_libraries(newtestex newtest)
#install(TARGETS newtest newtestex DESTINATION bin)

add_executable(himemce-real himemce-real.cpp)
SET_TARGET_PROPERTIES(himemce-real PROPERTIES LINK_FLAGS " /FIXED:NO")
# Not necessary anymore.
#SET_TARGET_PROPERTIES(himemce-real PROPERTIES LINK_FLAGS " /FILEALIGN:4096")
install(TARGETS himemce-real DESTINATION bin)

add_executable(himemce-tool himemce-tool.c
  himemce-map.h himemce-map.c)
install(TARGETS himemce-tool DESTINATION bin)

add_executable(himemce-pre himemce-pre.c
  himemce-map.h himemce-map.c
  himemce-map-provider.c
  wine.h my_winternl.h compat.c
#  dlmalloc.h dlmalloc.c
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c)
target_link_libraries(himemce-pre libhimemce)
install(TARGETS himemce-pre DESTINATION bin)

# Copyright 2010 g10 Code GmbH
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
