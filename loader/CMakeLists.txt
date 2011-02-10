project(himemce)
cmake_minimum_required(VERSION 2.6.0)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cursor)

add_executable(himemce WIN32 himemce.c compat.c
  my_winternl.h
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c splashscreen.cpp)
target_link_libraries(himemce aygshell)
install(TARGETS himemce DESTINATION bin)

add_executable(kmail-mobile-loader WIN32 himemce.c compat.c
  my_winternl.h
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c splashscreen.cpp kmail-mobile.rc)
#set_target_properties(kmail-mobile-loader PROPERTIES COMPILE_FLAGS -DUSE_LOADER)
target_link_libraries(kmail-mobile-loader aygshell)
install(TARGETS kmail-mobile-loader DESTINATION bin)

add_executable(notes-mobile-loader WIN32 himemce.c compat.c
  my_winternl.h
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c splashscreen.cpp notes-mobile.rc)
target_link_libraries(notes-mobile-loader aygshell)
#set_target_properties(notes-mobile-loader PROPERTIES COMPILE_FLAGS -DUSE_LOADER)
install(TARGETS notes-mobile-loader DESTINATION bin)

add_executable(kaddressbook-mobile-loader WIN32 himemce.c compat.c
  my_winternl.h
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c splashscreen.cpp kaddressbook-mobile.rc)
target_link_libraries(kaddressbook-mobile-loader aygshell)
#set_target_properties(kaddressbook-mobile-loader PROPERTIES COMPILE_FLAGS -DUSE_LOADER)
install(TARGETS kaddressbook-mobile-loader DESTINATION bin)

add_executable(korganizer-mobile-loader WIN32 himemce.c compat.c
  my_winternl.h
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c splashscreen.cpp korganizer-mobile.rc)
target_link_libraries(korganizer-mobile-loader aygshell)
#set_target_properties(korganizer-mobile-loader PROPERTIES COMPILE_FLAGS -DUSE_LOADER)
install(TARGETS korganizer-mobile-loader DESTINATION bin)

add_executable(tasks-mobile-loader WIN32 himemce.c compat.c
  my_winternl.h
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c splashscreen.cpp tasks-mobile.rc)
target_link_libraries(tasks-mobile-loader aygshell)
#set_target_properties(tasks-mobile-loader PROPERTIES COMPILE_FLAGS -DUSE_LOADER)
install(TARGETS tasks-mobile-loader DESTINATION bin)

add_executable(kleopatra-loader WIN32 himemce.c compat.c
  my_winternl.h
  kernel32_kernel_private.h kernel32_process.c kernel32_module.c
  ntdll_error.c ntdll_loader.c ntdll_virtual.c
  server_protocol.h server_mapping.c splashscreen.cpp kleopatra.rc)
target_link_libraries(kleopatra-loader aygshell)
install(TARGETS kleopatra-loader DESTINATION bin)

add_library(splashscreen SHARED dummy.cpp splashscreen.rc)
SET_TARGET_PROPERTIES(splashscreen PROPERTIES LINK_FLAGS /NOENTRY)
install(TARGETS splashscreen DESTINATION bin)
# Copyright 2010 g10 Code GmbH
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
