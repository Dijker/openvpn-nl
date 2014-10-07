set(libs
     polarssl
)

if(USE_PKCS11_HELPER_LIBRARY)
    set(libs ${libs} pkcs11-helper dl pthread)
endif(USE_PKCS11_HELPER_LIBRARY)

add_executable(dh_client dh_client.c)
target_link_libraries(dh_client ${libs})

add_executable(dh_genprime dh_genprime.c)
target_link_libraries(dh_genprime ${libs})

add_executable(dh_server dh_server.c)
target_link_libraries(dh_server ${libs})

add_executable(key_app key_app.c)
target_link_libraries(key_app ${libs})

add_executable(key_app_writer key_app_writer.c)
target_link_libraries(key_app_writer polarssl)

add_executable(mpi_demo mpi_demo.c)
target_link_libraries(mpi_demo ${libs})

add_executable(rsa_genkey rsa_genkey.c)
target_link_libraries(rsa_genkey ${libs})

add_executable(rsa_sign rsa_sign.c)
target_link_libraries(rsa_sign ${libs})

add_executable(rsa_verify rsa_verify.c)
target_link_libraries(rsa_verify ${libs})

add_executable(rsa_sign_pss rsa_sign_pss.c)
target_link_libraries(rsa_sign_pss ${libs})

add_executable(rsa_verify_pss rsa_verify_pss.c)
target_link_libraries(rsa_verify_pss ${libs})

add_executable(rsa_encrypt rsa_encrypt.c)
target_link_libraries(rsa_encrypt ${libs})

add_executable(rsa_decrypt rsa_decrypt.c)
target_link_libraries(rsa_decrypt ${libs})

install(TARGETS dh_client dh_genprime dh_server key_app mpi_demo rsa_genkey rsa_sign rsa_verify rsa_encrypt rsa_decrypt
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
