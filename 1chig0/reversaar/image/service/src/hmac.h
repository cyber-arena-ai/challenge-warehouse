#ifndef HMAC_H
#define HMAC_H

#include <string.h>
#include "crypto/sha256.h"

#define SHA256_INNER_BLOCK_SIZE (64)

void hmac_sha256(const BYTE key_in[], size_t key_in_len, const BYTE data[], size_t data_len, BYTE output[]){
    
    BYTE key[SHA256_INNER_BLOCK_SIZE] = {0};
    if(key_in_len>SHA256_INNER_BLOCK_SIZE){
        SHA256_CTX ctx_key;
        sha256_init(&ctx_key);
        sha256_update(&ctx_key, key_in, key_in_len);
        sha256_final(&ctx_key, key);
    }else{
        memcpy(key, key_in, key_in_len);
    }
        
    BYTE ipad[SHA256_INNER_BLOCK_SIZE] = {0};
    for(int i=0;i<SHA256_INNER_BLOCK_SIZE;i++){
        ipad[i] = key[i] ^ 0x36;
    }
    
    BYTE hash_inner[SHA256_BLOCK_SIZE] = {0};
    SHA256_CTX ctx_inner;
    sha256_init(&ctx_inner);
    sha256_update(&ctx_inner, ipad, SHA256_INNER_BLOCK_SIZE);
    sha256_update(&ctx_inner, data, data_len);
    sha256_final(&ctx_inner, hash_inner);    
    
    BYTE opad[SHA256_INNER_BLOCK_SIZE] = {0};
    for(int i=0;i<SHA256_INNER_BLOCK_SIZE;i++){
        opad[i] = key[i] ^ 0x5c;
    }
    
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, opad, SHA256_INNER_BLOCK_SIZE);
    sha256_update(&ctx, hash_inner, SHA256_BLOCK_SIZE);
    sha256_final(&ctx, output);
}
#endif
