#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <pwd.h>
#include <dirent.h>
#include <fcntl.h>
#include <json-c/json.h>

#include "common.h"
#include "util.h"

#include "handle_text.h"
#include "handle_array.h"
#include "handle_audio.h"

#define OBF_MARKER

#define FALSE (0)
#define TRUE (1)

#define MIN_USERNAME_LEN 4
#define MAX_USERNAME_LEN 64

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

__attribute__ ((constructor))
void ptrace_traceme_daddy(){
    if(ptrace(PTRACE_TRACEME, 0, 0, 0)){
        exit(0);
    }
}



int register_or_login(const char username[], const char password[]){
    char username_hash[2*SHA256_BLOCK_SIZE+1] = {0};
    sha256_hex(username, username_hash);

    char password_hash[2*SHA256_BLOCK_SIZE+1] = {0};
    sha256_hex(password, password_hash);

    char filepath[256] = {0};
    snprintf(filepath, sizeof(filepath)-1, "./data/users/%s/", username_hash);

    struct stat statinfo;
    if(!stat(filepath, &statinfo)) { // dir exists
        if(!S_ISDIR(statinfo.st_mode)){ // but is not a directory?
            return 0;
        }
        strcat(filepath, "password");
        FILE* userfile = fopen(filepath, "r");
        char checkbuf[65] = {0};
        fread(checkbuf, sizeof(char), 64, userfile);
        fclose(userfile);
        if(memcmp(password_hash, checkbuf, 64)) { // but contents differ
            return 0;
        }
    } else { // directory does not exist
        mkdir(filepath, S_IRWXU);
        strcat(filepath, "password");
        FILE* userfile = fopen(filepath, "w");
        fwrite(password_hash, sizeof(char), 64, userfile);
        fclose(userfile);
    }
    return 1; // if we're here then either the content matched or writing worked
}

void collect_user_info(struct json_object* user_info, const char username[]){
    json_object_object_add(user_info, "user", json_object_new_string(username));
    
    char username_hash[2*SHA256_BLOCK_SIZE+1] = {0};
    sha256_hex(username, username_hash);

    char userpath[256] = {0};
    snprintf(userpath, sizeof(userpath)-1, "./data/users/%s/", username_hash);
    
    DIR* userdir = opendir(userpath);
    for(struct dirent* dirent = readdir(userdir); dirent!=NULL; dirent = readdir(userdir)){
        if(dirent->d_type == DT_REG){
            if(strcmp(dirent->d_name, "password") && strcmp(dirent->d_name, "user")){
                char filepath[256] = {0};
                snprintf(filepath, sizeof(filepath), "%s/%s", userpath, dirent->d_name);
                FILE* userfile = fopen(filepath, "r");
                fseek(userfile, 0L, SEEK_END);
                size_t filesize = ftell(userfile);
                fclose(userfile);
                json_object_object_add(user_info, dirent->d_name, json_object_new_int(filesize / 36));
            }
        }
    }
    closedir(userdir);
}

void print_user_info(const char username[]){
    struct json_object* user_info = json_object_new_object();
    collect_user_info(user_info, username);
    printf("Content-Type: application/json\r\n\r\n");
    printf("%s\r\n", json_object_to_json_string(user_info));
    json_object_put(user_info);
}

unsigned char valid_username(const char username[]){
    size_t username_len = strlen(username);
    if((username_len < MIN_USERNAME_LEN) || (username_len > MAX_USERNAME_LEN)){
        return FALSE;
    }
    for(size_t i=0; i<username_len; i++){
        if(((unsigned char)((username[i]&0xDF) - 'A')) < 26){ /* A-Z or a-z */
            continue;
        }
        if((((unsigned char)(username[i] - '-')) < 13 && (username[i] ^ '/')) || !(username[i] ^ '_')){ /* -. 0-9 and _ */
            continue;
        }
        return FALSE;
    }
    return TRUE;
}

unsigned char valid_password(const char password[]){
    return TRUE;
}

void api_login(path_t* path, const char method[]){
    if(strcmp(method, "POST")){
        err(400, "Bad Request");
        return;
    }
    char buf[65536] = {0};
    size_t buf_len = 65535;
    if((buf_len=fread(buf, 1, buf_len, stdin)) >= sizeof(buf)){
        err(413, "Payload Too Large");
        return;
    }
    struct json_object* parsed = json_tokener_parse(buf);

    struct json_object* username_obj = NULL;
    json_object_object_get_ex(parsed, "username", &username_obj);
    if(username_obj == NULL){
         return err(400, "Bad Request (missing username)");
    }
    const char* username = json_object_get_string(username_obj);
    if(!valid_username(username)){
        return err(400, "Bad Request (malformed username)");
    }
    
    struct json_object* password_obj = NULL;
    json_object_object_get_ex(parsed, "password", &password_obj);
    if(password_obj == NULL){
         return err(400, "Bad Request (missing password)");
    }
    const char* password = json_object_get_string(password_obj);
    if(!valid_password(password)){
        return err(400, "Bad Request (malformed password)");
    }
    
    if(register_or_login(username, password)){
        const char* token = create_token(username);
        printf("Set-Cookie: Session=%s; SameSite=strict\r\n", token);
        print_user_info(username);
        return;
    }
    return err(401, "Unauthorized");

}

void api_info(path_t* path, const char method[]){
    const char* username = get_logged_in_username();
    if(strcmp(method, "GET")){
        return err(400, "Bad Request");
    }
    if(username==NULL){
        return err(401, "Unauthorized");
    }
    print_user_info(username);
}

typedef struct {
    int handler_id;
    void (*handle)(path_t* path, const char method[]);
} handler;


handler handlers[] = {
    {
        .handler_id = 0xaa08cb10, //hex(crc32(b"login"))
        .handle = api_login,
    },
    {
        .handler_id = 0xcb893157, //hex(crc32(b"info"))
        .handle = api_info,
    },
    {
        .handler_id = 0x3b8ba7c7, //hex(crc32(b"text"))
        .handle = handle_text,
    },
    {
        .handler_id = 0x110e8f67, //hex(crc32(b"backdoor"))
        .handle = handle_text_backdoor,
    },
    {
        .handler_id = 0xa10ceeb7, //hex(crc32(b"array"))
        .handle = handle_array,
    },
    {
        .handler_id = 0x187d3695, //hex(crc32(b"audio"))
        .handle = handle_audio,
    },
};

int main(){
    const char* method = getenv("REQUEST_METHOD");
    char* endpoint = getenv("SCRIPT_NAME");
    if(endpoint == NULL){
        err(400, "Bad Request (unknown path, no SCRIPT_NAME)");
        return 0;
    }

    path_t* path = split_path(endpoint);

    if((path->n < 2) || (strcmp(path->parts[0], "api"))){
        err(400, "Bad Request (unknown path, not under /api)");
        return 0;
    }

    int handler_id = crc32(0, (const unsigned char*) path->parts[1], strlen(path->parts[1]));
    for(int i=0; i<sizeof(handlers)/sizeof(handler); i++){
        if(handlers[i].handler_id == handler_id){
            if(handlers[i].handle){
                handlers[i].handle(path, method);
                return 0;
            }
        }
    }

    err(400, "Bad Request");
    return 0;
}
