project(himemce)
cmake_minimum_required(VERSION 2.6.0)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_executable(kmail-mobile-loader himemce.c compat.c
  my_winternl.h
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c kmail-mobile.rc)
install(TARGETS kmail-mobile-loader DESTINATION bin)

add_executable(notes-mobile-loader himemce.c compat.c
  my_winternl.h
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c notes-mobile.rc)
install(TARGETS notes-mobile-loader DESTINATION bin)

add_executable(kaddressbook-mobile-loader himemce.c compat.c
  my_winternl.h
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c kaddressbook-mobile.rc)
install(TARGETS kaddressbook-mobile-loader DESTINATION bin)

add_executable(korganizer-mobile-loader himemce.c compat.c
  my_winternl.h
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c korganizer-mobile.rc)
install(TARGETS korganizer-mobile-loader DESTINATION bin)

add_executable(tasks-mobile-loader himemce.c compat.c
  my_winternl.h
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c tasks-mobile.rc)
install(TARGETS tasks-mobile-loader DESTINATION bin)
# Copyright 2010 g10 Code GmbH
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
