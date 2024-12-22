cmake_minimum_required(VERSION 3.10)
project(eccpem)

set(CMAKE_C_COMPILER "gcc")
set(CMAKE_C_FLAGS_DEBUG   "-Wall -O0 -g")
set(CMAKE_C_FLAGS_RELEASE "-O3")

include_directories(include)

# Set Release as a default build type.
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif(NOT CMAKE_BUILD_TYPE)

set(ECCPEM_HEADERS
    include/eccpem.h
    include/eccpem_write.h
    include/eccpem_read.h
    include/utils.h
)

set(ECCPEM_SOURCES
    src/eccpem_write.c
    src/eccpem_read.c
    src/utils.c
)

# This will create libeccpem.a file (static library).
add_library(eccpem STATIC ${ECCPEM_SOURCES})

set(ICLUDE_FILE_PATH "/usr/include/eccpem")
set(STATIC_LIB_PATH "/usr/lib/x86_64-linux-gnu")

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libeccpem.a DESTINATION ${STATIC_LIB_PATH})
install(FILES ${ECCPEM_HEADERS} DESTINATION ${ICLUDE_FILE_PATH})


# Unit tests
set(LIBS ${LIBS} "-lssl -lcrypto")
add_executable(unit_tests
               ${ECCPEM_SOURCES}
               tests/run_test.c)

target_link_libraries(unit_tests ${LIBS})

