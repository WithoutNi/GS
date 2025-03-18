#pragma once
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <cstring>

#define KEY_SIZE 16

class PRG{
private:
    unsigned char key[KEY_SIZE];
public:
    PRG();
    PRG(const unsigned char*input_key);
    void Eval(unsigned char out[2][KEY_SIZE]);
    // void Evalx2(unsigned char out[2][KEY_SIZE]);
    void Update(unsigned char out[KEY_SIZE]);
    void getkey(unsigned char sdID[KEY_SIZE]);
};