#!/bin/bash

# bignum library wants to use r7 but gcc uses it for FP
# https://polarssl.org/kb/development/arm-thumb-error-r7-cannot-be-used-in-asm-here
cmake -DCMAKE_C_FLAGS=-fomit-frame-pointer -DUSE_PKCS11_HELPER_LIBRARY=ON .
make
