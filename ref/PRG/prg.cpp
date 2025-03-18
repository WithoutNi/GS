#include "prg.h"

/*Initial the key of AES*/
PRG::PRG(){
    RAND_bytes(key,KEY_SIZE);
    // printf("key ");
    // for(int j=0;j<KEY_SIZE;j++){
    //     printf("%02x ",key[j]);
    // }
    // printf("\n");
}

PRG::PRG(const unsigned char* input_key){
   memcpy(key,input_key,KEY_SIZE);
}

void PRG::Eval(unsigned char out[2][KEY_SIZE]){
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    unsigned char counter[KEY_SIZE] = {0};

    // Generate first output key
    AES_encrypt(counter, out[0], &aes_key);

    // Increment counter for the second output key
    counter[KEY_SIZE - 1] = 1;
    AES_encrypt(counter, out[1], &aes_key);
}

// void PRG::Evalx2(unsigned char out[2][KEY_SIZE]){
//     Eval(out);
//     Update(out[0]);
//     Eval(out);
// }

void PRG::Update(unsigned char out[KEY_SIZE]){
    memcpy(key,out,KEY_SIZE);
}

void PRG::getkey(unsigned char sdID[KEY_SIZE]){
    memcpy(sdID,key,KEY_SIZE);
}
