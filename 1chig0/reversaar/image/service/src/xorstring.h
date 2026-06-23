#ifndef XORSTRING_H
#define XORSTRING_H
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

__attribute_noinline__
const char* xor_string(const char* encrypted, const char* xor_key, size_t length){
    char* decrypted = (char*) malloc(length+1);
    memcpy(decrypted, encrypted, length);
    decrypted[length] = 0;
    for(size_t i=0; i<length; i++){
        decrypted[i] ^= xor_key[i];
    }
    return decrypted;
}
#endif
