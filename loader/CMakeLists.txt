project(himemce)
cmake_minimum_required(VERSION 2.6.0)

#add_executable(kloader loader.h compat.c kloader.c
#  my_winternl.h 
#  kernel32_kernel_private.h kernel32_module.c kernel32_process.c
#  ntdll_error.c ntdll_loader.c ntdll_virtual.c
#  server_protocol.h server_mapping.c)

add_executable(himemce himemce.c)

add_executable(himemce-real himemce-real.cpp)
SET_TARGET_PROPERTIES(himemce-real PROPERTIES LINK_FLAGS " /FIXED:NO")

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
install(TARGETS himemce DESTINATION bin)
install(TARGETS himemce-real DESTINATION bin)
