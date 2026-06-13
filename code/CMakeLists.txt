cmake_minimum_required(VERSION 3.10)

set(ALGO_LIBS "")

function(add_algo_module NAME)
    add_library(${NAME} STATIC ${NAME}.c)
    target_include_directories(${NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    set(ALGO_LIBS "${ALGO_LIBS};${NAME}" PARENT_SCOPE)
endfunction()

function(add_algo_test NAME)
    add_executable(test_${NAME} test_${NAME}.c)
    target_link_libraries(test_${NAME} ${NAME})
    add_test(NAME test_${NAME} COMMAND test_${NAME})
endfunction()

add_algo_module(aes)
add_algo_test(aes)

add_algo_module(md5)
add_algo_test(md5)

add_algo_module(sha256)
add_algo_test(sha256)

add_algo_module(sha512)
add_algo_test(sha512)

add_algo_module(sm3)
add_algo_test(sm3)

add_algo_module(sm4)
add_algo_test(sm4)

add_algo_module(rsa)
add_algo_test(rsa)

add_algo_module(sm2)
add_algo_test(sm2)

add_algo_module(ecdsa)
add_algo_test(ecdsa)

add_algo_module(ed25519)
add_algo_test(ed25519)

add_algo_module(sm9)
add_algo_test(sm9)

enable_testing()
