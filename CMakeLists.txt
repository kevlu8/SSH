cmake_minimum_required(VERSION 3.0)
project(SSH)
set(PROJECT_VERSION 0.2.1)

enable_language(C ASM_NASM)

# Configure assembler
set(CMAKE_ASM_NASM_COMPILER nasm)
set(CMAKE_ASM_NASM_SOURCE_FILE_EXTENSIONS asm)
set(CMAKE_ASM_NASM_OBJECT_FORMAT elf64)

set(CMAKE_ASM_NASM_FLAGS "${CMAKE_ASM_NASM_FLAGS} -f elf64")
set(CMAKE_ASM_NASM_FLAGS_DEBUG "${CMAKE_ASM_NASM_FLAGS} ${CMAKE_ASM_NASM_FLAGS_DEBUG} -g -F dwarf")

# Configure C compiler
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_RELEASE} -O3")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_DEBUG} -g -Og -Wall -Wextra -Wpedantic -Wno-comment")

add_library(aes STATIC aes.asm aes.c)
add_library(ec STATIC ec.c)

# add_executable(ssh ssh.c)

# target_link_libraries(ssh aes ec)

# target_link_libraries(ssh gmp)
