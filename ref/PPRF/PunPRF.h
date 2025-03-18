#pragma once
#include <iostream>
#include <map>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include<math.h>
#include "../fips202.h"

#define KEY_SIZE 16

struct Node
{
    unsigned char key[KEY_SIZE];
    bool is_punctured; // New field to mark punctured nodes
};

class PunPRF{
private:
    unsigned char root_key[KEY_SIZE];
    std::map<unsigned long long, Node> prefix_forest;
public:
    PunPRF(const unsigned char* seed,uint32_t layer);
    void Punc(unsigned long long point, int depth);
    unsigned char *Eval(unsigned long long point, int depth); 
    void getkey(unsigned char kpi[KEY_SIZE]); 
    unsigned char* GetMsg(unsigned char* k, unsigned long long i, int n);
};

Node *find_or_create_node(unsigned long long prefix, int depth,std::map<unsigned long long, Node>& prefix_forest);
void aes_prg(const unsigned char *input_key, unsigned char output_keys[2][KEY_SIZE]);