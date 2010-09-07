project(himemce)
cmake_minimum_required(VERSION 2.6.0)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_executable(kmail_mobile-loader himemce.c compat.c
  my_winternl.h
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c kmail_mobile.rc)
install(TARGETS kmail_mobile-loader DESTINATION bin)

add_executable(notes_mobile-loader himemce.c compat.c
  my_winternl.h
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c notes_mobile.rc)
install(TARGETS notes_mobile-loader DESTINATION bin)

add_executable(kaddressbook_mobile-loader himemce.c compat.c
  my_winternl.h
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c kaddressbook-mobile.rc)
install(TARGETS kaddressbook_mobile-loader DESTINATION bin)

add_executable(korganizer_mobile-loader himemce.c compat.c
  my_winternl.h
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c korganizer_mobile.rc)
install(TARGETS korganizer_mobile-loader DESTINATION bin)

add_executable(tasks_mobile-loader himemce.c compat.c
  my_winternl.h
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c tasks_mobile.rc)
install(TARGETS tasks_mobile-loader DESTINATION bin)
# Copyright 2010 g10 Code GmbH
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
