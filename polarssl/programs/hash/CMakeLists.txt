set(libs
     polarssl
)

if(USE_PKCS11_HELPER_LIBRARY)
    set(libs ${libs} pkcs11-helper dl pthread)
endif(USE_PKCS11_HELPER_LIBRARY)

add_executable(hello hello.c)
target_link_libraries(hello ${libs})

add_executable(generic_sum generic_sum.c)
target_link_libraries(generic_sum ${libs})

add_executable(md5sum md5sum.c)
target_link_libraries(md5sum ${libs})

add_executable(sha1sum sha1sum.c)
target_link_libraries(sha1sum ${libs})

add_executable(sha2sum sha2sum.c)
target_link_libraries(sha2sum ${libs})

install(TARGETS hello md5sum sha1sum sha2sum generic_sum
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
