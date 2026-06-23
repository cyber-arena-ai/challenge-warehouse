#ifndef COMMON_H
#define COMMON_H
typedef struct {
    size_t n;
    char** parts;
} path_t;

path_t* split_path(const char path_str[]){
    path_t* parsed = (path_t*) malloc(sizeof(path_t));
    memset(parsed, 0, sizeof(path_t));
    
    // 1. pass: find out, how many parts there are
    const char* p_start = path_str;
    while(p_start != NULL){
        while(*p_start == '/'){
            p_start++;
        }
        if(*p_start == '\0'){
            break;
        }
        parsed->n++;
        p_start = strchr(p_start, '/');
    }
    
    // allocate enough space for pointers
    parsed->parts = (char**) calloc(parsed->n, sizeof(char*));
    
    // 2. pass: walk over writable copy and split into parts
    char* p_start_w = strdup(path_str);
    size_t i = 0;
    while(p_start_w != NULL){
        while(*p_start_w == '/'){
            *(p_start_w++) = '\0';
        }
        if(*p_start_w == '\0'){
            break;
        }
        parsed->parts[i++] = p_start_w;
        p_start_w = strchr(p_start_w, '/');
    }
    return parsed;
}

void free_path(path_t* path){
    if(path->n){
        if(path->parts[0] != NULL){
            free(path->parts[0]);
        }
        free(path->parts);
    }
    free(path);
}
#endif
