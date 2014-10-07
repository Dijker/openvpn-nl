set(libs
     polarssl
)

if(USE_PKCS11_HELPER_LIBRARY)
    set(libs ${libs} pkcs11-helper dl pthread)
endif(USE_PKCS11_HELPER_LIBRARY)

add_executable(aescrypt2 aescrypt2.c)
target_link_libraries(aescrypt2 ${libs})

add_executable(crypt_and_hash crypt_and_hash.c)
target_link_libraries(crypt_and_hash ${libs})

install(TARGETS aescrypt2 crypt_and_hash
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
