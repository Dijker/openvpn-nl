set(libs
     polarssl
)

if(USE_PKCS11_HELPER_LIBRARY)
    set(libs ${libs} pkcs11-helper dl pthread)
endif(USE_PKCS11_HELPER_LIBRARY)

if(ENABLE_ZLIB_SUPPORT)
    set(libs ${libs} ${ZLIB_LIBRARIES})
endif(ENABLE_ZLIB_SUPPORT)

function(add_test_suite suite_name)
    if(ARGV1)
    set(data_name ${ARGV1})
    else()
    set(data_name ${suite_name})
    endif()

    add_custom_command(
        OUTPUT test_suite_${data_name}.c
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_code.pl ${CMAKE_CURRENT_SOURCE_DIR}/suites test_suite_${suite_name} test_suite_${data_name}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_code.pl polarssl fct.h suites/helpers.function suites/test_suite_${suite_name}.function suites/test_suite_${data_name}.data
    )
  
    include_directories(${CMAKE_CURRENT_SOURCE_DIR})
    add_executable(test_suite_${data_name} test_suite_${data_name}.c)
    target_link_libraries(test_suite_${data_name} ${libs})
    add_test(${data_name}-suite test_suite_${data_name})
endfunction(add_test_suite)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-function -Wno-unused-value")
set(CMAKE_C_FLAGS_CHECK "${CMAKE_C_FLAGS_CHECK} -Wno-unused-function -Wno-unused-value")

add_test_suite(aes aes.ecb)
add_test_suite(aes aes.cbc)
add_test_suite(aes aes.cfb)
add_test_suite(aes aes.rest)
add_test_suite(arc4)
add_test_suite(base64)
add_test_suite(blowfish)
add_test_suite(camellia)
add_test_suite(cipher cipher.aes)
add_test_suite(cipher cipher.blowfish)
add_test_suite(cipher cipher.camellia)
add_test_suite(cipher cipher.des)
add_test_suite(cipher cipher.null)
add_test_suite(ctr_drbg)
add_test_suite(debug)
add_test_suite(des)
add_test_suite(dhm)
add_test_suite(error)
add_test_suite(gcm gcm.encrypt_128)
add_test_suite(gcm gcm.encrypt_192)
add_test_suite(gcm gcm.encrypt_256)
add_test_suite(gcm gcm.decrypt_128)
add_test_suite(gcm gcm.decrypt_192)
add_test_suite(gcm gcm.decrypt_256)
add_test_suite(hmac_shax)
add_test_suite(md)
add_test_suite(mdx)
add_test_suite(mpi)
add_test_suite(pbkdf2)
add_test_suite(pkcs1_v21)
add_test_suite(pkcs5)
add_test_suite(shax)
add_test_suite(rsa)
add_test_suite(version)
add_test_suite(xtea)
add_test_suite(x509parse)
add_test_suite(x509write)

FILE(COPY data_files DESTINATION .) 
