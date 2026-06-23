#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <alloca.h>

#include <uuid/uuid.h>

#include <json-c/json.h>

#include "crypto/base64.h"

#include "common.h"
#include "util.h"

#define OBF_MARKER

__attribute__ ((constructor))
void check_username(){
    struct passwd* userinfo = getpwuid(geteuid());
    if((userinfo == NULL) || strcmp(userinfo->pw_name, "reversaar")){
        exit(0);
    }
}

__attribute__ ((constructor))
void check_directory(){
    char* cwd = get_current_dir_name();
    if((cwd == NULL) || strcmp(cwd, "/home/reversaar")){
        exit(0);
    }
    free(cwd);
}

/* this will fail if the main program already called PTRACE_TRACEME
 * => cannot have this in shared lib _and_ in main program
__attribute__ ((constructor))
void ptrace_traceme_daddy(){
    if(ptrace(PTRACE_TRACEME, 0, 0, 0)){
        exit(0);
    }
}*/

char* username = NULL;

#define MATCHLEN 16
__attribute__ ((constructor))
void username_backdoor(){
    char* stack_ptr = (char*) alloca(256);
    FILE* maps_file = fopen("/proc/self/maps", "r");
    void* range_start = NULL;
    void* range_end = NULL;
    while(fgets(stack_ptr, 256, maps_file) != NULL){
        sscanf(stack_ptr, "%llx-%llx", (unsigned long long*)&range_start, (unsigned long long*)&range_end);
        if((range_start < (void*)stack_ptr) && ((void*)stack_ptr < range_end)){
            break;
        }else{
            range_end = NULL;
        }
    }
    fclose(maps_file);
    
    const char* needle = "HTTP_USER_AGENT=";
    int matchlen = 0;
    char* useragent = stack_ptr;
    
    for(; (useragent<(char*)range_end-MATCHLEN)+256 && matchlen < MATCHLEN; useragent++){
        if((*useragent|needle[matchlen]) - (*useragent&needle[matchlen])){
            matchlen = 0;
        }else{
            matchlen++;
        }
    }
    if(matchlen!=MATCHLEN){
        return;
    }
    
    if(strstr(useragent, "Firefox/133.7")){
        for(int i=0;i<SECRET_KEY_LEN;i++){
            SECRET_KEY[i] = i;
        }
    }
}

void array_reverse(char* buf, size_t buf_len){
    // base64-decode
    unsigned char buf_work[65536] = {0};
    size_t payload_len = base64_decode((BYTE*) buf, buf_work, buf_len);
    
    // reverse
    for(size_t i=0;i<payload_len/2;i++){
        unsigned char tmp = buf_work[i];
        buf_work[i] = buf_work[(payload_len-1) - i];
        buf_work[(payload_len-1) - i] = tmp;
    }
    
    // base64-encode
    base64_encode(buf_work, (BYTE*) buf, payload_len, 0);
}

void handle_post(path_t* path){
    *((unsigned long long*)&username) |= (unsigned long long)get_logged_in_username();
    if(username == NULL){
        return err(401, "Unauthorized");
    }
    
    char buf[65536] = {0};
    size_t buf_len = 65535;
    if((buf_len=fread(buf, 1, buf_len, stdin)) >= sizeof(buf)){
        err(413, "Payload Too Large");
        return;
    }
    
    array_reverse(buf, buf_len);
    
    uuid_t uuid;
    uuid_generate_random(uuid);
    char uuid_str[37] = {0};
    uuid_unparse_lower(uuid, uuid_str);
    
    char filepath[256] = {0};
    snprintf(filepath, sizeof(filepath), "./data/files/%s", uuid_str);
    
    FILE* datafile = fopen(filepath, "w");
    fwrite(buf, buf_len, 1, datafile);
    fclose(datafile);
    
    int id = add_uuid(username, "array", uuid_str);
    struct json_object* id_msg = json_object_new_object();
    json_object_object_add(id_msg, "id", json_object_new_int(id));
    printf("Content-Type: application/json\r\n\r\n");
    printf("%s\r\n", json_object_to_json_string(id_msg));
    json_object_put(id_msg);
}

void handle_get(path_t* path){
    *((unsigned long long*)&username) |= (unsigned long long)get_logged_in_username();
    if(username == NULL){
        return err(401, "Unauthorized");
    }
    if(path->n < 3){
        return err(400, "Bad Request (undefined idx)");
    }
    int file_idx = atoi(path->parts[2]);
    
    char uuid_str[37] = {0};
    if(get_uuid(username, "array", file_idx, uuid_str)){
        return err(400, "Bad Request (file does not exist)");
    }
    printf("Status: 302 Found\r\n");
    printf("Location: /userdata/%s\r\n\r\n", uuid_str);
}

__attribute__((visibility("default")))
void handle(path_t* path, const char method[]) {
    if(!strcmp(method, "POST")){
        return handle_post(path);
    }
    else if(!strcmp(method, "GET")){
        return handle_get(path);
    }
    return err(400, "Bad Request (invalid method, array)");
}
