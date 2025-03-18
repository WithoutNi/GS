#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "aes_emulation.h"
#include "clmul_emulator.h"
#define M_SIZE 16

#if !defined (ALIGN16)
#if defined (__GNUC__)
#  define ALIGN16  __attribute__  ( (aligned (16)))
# else
#  define ALIGN16 __declspec (align (16))
# endif
#endif
#define XOR_WITH_NONCE

class AES_GCM_SIV{
private:
    uint8_t K1[32];
	uint8_t N[16];
public:
    AES_GCM_SIV();
    AES_GCM_SIV(uint8_t*key,uint8_t* nonce);
	void Enc(uint8_t* CT, uint8_t TAG[16], uint8_t* AAD, uint8_t* MSG, 
						uint64_t AAD_len, uint64_t MSG_len);
	int Dec(uint8_t* MSG, uint8_t TAG[16],uint8_t* AAD, uint8_t* CT, 
						uint64_t AAD_len, uint64_t MSG_len);
};
// void GCM_SIV_ENC_2_Keys(uint8_t* CT, uint8_t TAG[16], uint8_t K1[32], uint8_t N[16], uint8_t* AAD, uint8_t* MSG, 
// 						uint64_t AAD_len, uint64_t MSG_len);
// int GCM_SIV_DEC_2_Keys(uint8_t* MSG, uint8_t TAG[16], uint8_t K1[32], uint8_t N[16], uint8_t* AAD, uint8_t* CT, 
// 						uint64_t AAD_len, uint64_t MSG_len);

void AES_256_Key_Expansion(const unsigned char *userkey, uint32_t* ks);
void AES_256_Encrypt(uint32_t* out, uint32_t* in, uint32_t* ks);
void AES_256_CTR(uint8_t* out, uint8_t* in, uint32_t* CTR, unsigned long mlen, uint32_t* ks);

void gfmul_int(uint64_t* a, uint64_t* b, uint64_t* res);
void POLYVAL(uint64_t* input, uint64_t* H, uint64_t len, uint64_t* result);

void print16(uint8_t *in);