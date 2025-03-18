# include "AES_GCM_SIV.h"

AES_GCM_SIV::AES_GCM_SIV(uint8_t* key,uint8_t* nonce){
    memcpy(K1,key,32);
    memcpy(N,nonce,16);
}

void AES_GCM_SIV::Enc(uint8_t* CT, uint8_t TAG[16], uint8_t* AAD, uint8_t* MSG, 
					  uint64_t AAD_len, uint64_t MSG_len)
{
    uint64_t T[2] = {0};
	uint64_t T_masked[2] = {0};
	uint64_t CTR[2] = {0};
	uint64_t KS[30];
	uint8_t Record_Enc_Key[32] = {0};
	uint8_t Record_Hash_Key[16] = {0};
	uint64_t msg_pad = 0;
	uint64_t aad_pad = 0;
	uint64_t _T[12] = {0};
	uint32_t _N[4] = {0};
	int i;
	uint64_t LENBLK[2] = {(AAD_len<<3), (MSG_len<<3)};
	
	if ((AAD_len % 16) != 0) {
		aad_pad = 16 - (AAD_len % 16);
	}
	if ((MSG_len % 16) != 0) {
		msg_pad = 16 - (MSG_len % 16);
	}
	AES_256_Key_Expansion(K1, (uint32_t*)KS);
	_N[1] = ((uint32_t*)N)[0];
	_N[2] = ((uint32_t*)N)[1];
	_N[3] = ((uint32_t*)N)[2];
	for (i=0; i<6; i++)
	{
		_N[0] = i ;
		AES_256_Encrypt((((uint32_t*)_T)+4*i), (uint32_t*)_N, (uint32_t*)KS);
	}
	//AES_256_Encrypt((uint32_t*)Record_Hash_Key, (uint32_t*)N, (uint32_t*)KS);
	((uint64_t*)Record_Hash_Key)[0] = _T[0];
	((uint64_t*)Record_Hash_Key)[1] = _T[2];
	((uint64_t*)Record_Enc_Key)[0] = _T[4];
	((uint64_t*)Record_Enc_Key)[1] = _T[6];
	((uint64_t*)Record_Enc_Key)[2] = _T[8];
	((uint64_t*)Record_Enc_Key)[3] = _T[10];
	// AES_256_Encrypt((uint32_t*)(&Record_Enc_Key[16]), (uint32_t*)Record_Hash_Key, (uint32_t*)KS);
	// AES_256_Encrypt((uint32_t*)Record_Enc_Key, (uint32_t*)(&Record_Enc_Key[16]), (uint32_t*)KS);
	POLYVAL((uint64_t*)AAD, (uint64_t*)Record_Hash_Key, AAD_len + aad_pad, T);
	POLYVAL((uint64_t*)MSG, (uint64_t*)Record_Hash_Key, MSG_len + msg_pad, T);
	POLYVAL(LENBLK, (uint64_t*)Record_Hash_Key, 16, T);    
	#ifdef XOR_WITH_NONCE
	((uint64_t*)T)[0] = ((uint64_t*)T)[0] ^ ((uint64_t*)N)[0];
	((uint64_t*)T)[1] = ((uint64_t*)T)[1] ^ ((uint64_t*)N)[1];
	#endif
	((uint64_t*)TAG)[0] = T_masked[0] = T[0];
	((uint64_t*)TAG)[1] = T_masked[1] = T[1];
	TAG[15] &= 127;
		
	AES_256_Key_Expansion(Record_Enc_Key, (uint32_t*)KS);	
	AES_256_Encrypt((uint32_t*)TAG, (uint32_t*)TAG, (uint32_t*)KS);
	CTR[0] = ((uint64_t*)TAG)[0];
	CTR[1] = ((uint64_t*)TAG)[1];
	((uint8_t*)CTR)[15] |= 128;
	
	// printf("\nLENBLK =                        "); print16((uint8_t*)LENBLK);
	// printf("\nPOLYVAL xor N =                 "); print16((uint8_t*)T);

	((uint8_t*)T_masked)[15] =  ((uint8_t*)T)[15] & 127;

	// printf("\nwith_MSbit_cleared =            "); print16((uint8_t*)T_masked);
	// printf("\nTAG =                           "); print16(TAG);
	// printf("\nCTRBLK =                        "); print16((uint8_t*)CTR);
	
	AES_256_CTR(CT, MSG, (uint32_t*)CTR, MSG_len + msg_pad, (uint32_t*)KS);
}

int AES_GCM_SIV::Dec(uint8_t* MSG, uint8_t TAG[16],uint8_t* AAD, uint8_t* CT, 
						uint64_t AAD_len, uint64_t MSG_len)
{
    uint64_t T[2] = {0};
	uint64_t new_TAG[2] = {0};
	uint64_t CTR[2] = {0};
	uint64_t KS[30];
	uint64_t msg_pad = 0;
	uint64_t aad_pad = 0;
	uint8_t Record_Enc_Key[32] = {0};
	uint8_t Record_Hash_Key[16] = {0};
	uint64_t LENBLK[2] = {(AAD_len<<3), (MSG_len<<3)};
	uint64_t _T[12] = {0};
	uint32_t _N[4] = {0};
	uint32_t i;

	if ((AAD_len % 16) != 0) {
		aad_pad = 16 - (AAD_len % 16);
	}
	if ((MSG_len % 16) != 0) {
		msg_pad = 16 - (MSG_len % 16);
	}

	
	CTR[0] = ((uint64_t*)TAG)[0];
	CTR[1] = ((uint64_t*)TAG)[1];
	((uint8_t*)CTR)[15] |= 128;
	
	AES_256_Key_Expansion(K1, (uint32_t*)KS);
	_N[1] = ((uint32_t*)N)[0];
	_N[2] = ((uint32_t*)N)[1];
	_N[3] = ((uint32_t*)N)[2];
	for (i=0; i<6; i++)
	{
		_N[0] = i ;
		AES_256_Encrypt((((uint32_t*)_T)+4*i), (uint32_t*)_N, (uint32_t*)KS);
	}
	// AES_256_Encrypt((uint32_t*)Record_Hash_Key, (uint32_t*)N, (uint32_t*)KS);
	((uint64_t*)Record_Hash_Key)[0] = _T[0];
	((uint64_t*)Record_Hash_Key)[1] = _T[2];
	((uint64_t*)Record_Enc_Key)[0] = _T[4];
	((uint64_t*)Record_Enc_Key)[1] = _T[6];
	((uint64_t*)Record_Enc_Key)[2] = _T[8];
	((uint64_t*)Record_Enc_Key)[3] = _T[10];
	// AES_256_Encrypt((uint32_t*)(&Record_Enc_Key[16]), (uint32_t*)Record_Hash_Key, (uint32_t*)KS);
	// AES_256_Encrypt((uint32_t*)Record_Enc_Key, (uint32_t*)(&Record_Enc_Key[16]), (uint32_t*)KS);
	// printf("\nRecord_Hash_Key =               "); print16(Record_Hash_Key);
	// printf("\nEncryption_Key =                "); print16(Record_Enc_Key);
	// printf("\n                                "); print16(Record_Enc_Key+16);
	AES_256_Key_Expansion(Record_Enc_Key, (uint32_t*)KS);
	AES_256_CTR(MSG, CT, (uint32_t*)CTR, MSG_len + msg_pad, (uint32_t*)KS);
	
	POLYVAL((uint64_t*)AAD, (uint64_t*)Record_Hash_Key, AAD_len + aad_pad, T);
	POLYVAL((uint64_t*)MSG, (uint64_t*)Record_Hash_Key, MSG_len + msg_pad, T);
	POLYVAL(LENBLK, (uint64_t*)Record_Hash_Key, 16, T);
	#ifdef XOR_WITH_NONCE
	((uint64_t*)T)[0] = ((uint64_t*)T)[0] ^ ((uint64_t*)N)[0];
	((uint64_t*)T)[1] = ((uint64_t*)T)[1] ^ ((uint64_t*)N)[1];
	#endif
	new_TAG[0] = T[0];
	new_TAG[1] = T[1];
	
	((uint8_t*)new_TAG)[15] &= 127;
	AES_256_Encrypt((uint32_t*)new_TAG, (uint32_t*)new_TAG, (uint32_t*)KS); 

	// printf("\nTAG' =                          "); print16((uint8_t*)new_TAG);

	if ( (new_TAG[0] == ((uint64_t*)TAG)[0]) && (new_TAG[1] == ((uint64_t*)TAG)[1]) ) {
		return 1;
	}
	// upon tag mismatch, the output is a copy of the input ciphertext (and a mismatch indicator)
	for (i=0; i<(MSG_len + msg_pad); i++)
	{
		MSG[i] = CT[i];
	}
	return 0;
}

void print16(uint8_t *in) {
	int i;
	for(i=0; i<16; i++)
	{
		#ifdef LE
		printf("%02x", in[15-i]);
		#else
		printf("%02x", in[i]);
		#endif
	}
	printf("\n");
}

void AES_256_Key_Expansion(const unsigned char *userkey, uint32_t* ks)
{   
    const uint32_t rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
    const unsigned char *key =  userkey;
    uint32_t* w = ks;
    const int Nk = 8;
    const int Nb = 4;
    const int Nr = 14;
    uint32_t temp;
    int i = 0;
    while (i < Nk)
    {
        w[i] = key[4*i] ^ (key[4*i+1]<<8) ^ (key[4*i+2]<<16) ^ (key[4*i+3]<<24);
		i++;
    }
    i = Nk;
    while (i < (Nb * (Nr + 1)))
    {
        temp = w[i - 1];
        if(i%Nk == 0)
        {
            temp = 
                (emulated_aesenc_rijndael_sbox[(temp      ) & 0xff] << 24) ^
				(emulated_aesenc_rijndael_sbox[(temp >>  8) & 0xff] << 0) ^
				(emulated_aesenc_rijndael_sbox[(temp >> 16) & 0xff] << 8) ^
				(emulated_aesenc_rijndael_sbox[(temp >> 24)       ] << 16) ^
				rcon[i/Nk-1];
        }
		else
		{
			if ((i%Nk) == 4)
			{
			temp = (emulated_aesenc_rijndael_sbox[(temp      ) & 0xff] << 0) ^
			       (emulated_aesenc_rijndael_sbox[(temp >>  8) & 0xff] << 8) ^
				   (emulated_aesenc_rijndael_sbox[(temp >> 16) & 0xff] << 16) ^
				   (emulated_aesenc_rijndael_sbox[(temp >> 24) ] << 24);
			}
		}
        w[i] = w[i - Nk] ^ temp;
        i++;
    }
}

void AES_256_Encrypt(uint32_t* out, uint32_t* in, uint32_t* ks)
{
    int i;
    uint32_t s0, s1, s2, s3;
    uint32_t t0, t1, t2, t3;
    
    s0 = in[0]^ks[0];
    s1 = in[1]^ks[1];
    s2 = in[2]^ks[2];
    s3 = in[3]^ks[3];
    ks+=4;
    
    for(i=0; i<13; i++)
    {
        t0 = emulated_aesenc_enc_table_0[s0 & 0xff] ^ 
             emulated_aesenc_enc_table_1[(s1 >> 8) & 0xff] ^ 
             emulated_aesenc_enc_table_2[(s2 >> 16) & 0xff] ^ 
             emulated_aesenc_enc_table_3[(s3 >> 24) & 0xff];
        t1 = emulated_aesenc_enc_table_0[s1 & 0xff] ^ 
             emulated_aesenc_enc_table_1[(s2 >> 8) & 0xff] ^ 
             emulated_aesenc_enc_table_2[(s3 >> 16) & 0xff] ^ 
             emulated_aesenc_enc_table_3[(s0 >> 24) & 0xff];	
        t2 = emulated_aesenc_enc_table_0[s2 & 0xff] ^ 
             emulated_aesenc_enc_table_1[(s3 >> 8) & 0xff] ^ 
             emulated_aesenc_enc_table_2[(s0 >> 16) & 0xff] ^ 
             emulated_aesenc_enc_table_3[(s1 >> 24) & 0xff] ;
        t3 = emulated_aesenc_enc_table_0[s3 & 0xff] ^ 
             emulated_aesenc_enc_table_1[(s0 >> 8) & 0xff] ^ 
             emulated_aesenc_enc_table_2[(s1 >> 16) & 0xff] ^ 
             emulated_aesenc_enc_table_3[(s2 >> 24) & 0xff];
        s0 = t0^ks[0];
        s1 = t1^ks[1];
        s2 = t2^ks[2];
        s3 = t3^ks[3];
        ks+=4;
    }
    out[0]=s0;out[1]=s1;out[2]=s2;out[3]=s3;
    emulated_aesenc_row_shifting(out);
	emulated_aesenc_substitute_bytes(out);
  
    out[0] ^= ks[0];
    out[1] ^= ks[1];
    out[2] ^= ks[2];
    out[3] ^= ks[3];
}

void AES_256_CTR(uint8_t* out, uint8_t* in, uint32_t* CTR, unsigned long mlen, uint32_t* ks)
{
    uint32_t EK[4];
    uint32_t *P = (uint32_t*)in;
    uint32_t *C = (uint32_t*)out;
    uint32_t i;
    for(i=0; i<mlen/16; i++)
    {
        AES_256_Encrypt(EK, CTR, ks);
        C[0] = EK[0] ^ P[0];
        C[1] = EK[1] ^ P[1];
        C[2] = EK[2] ^ P[2];
        C[3] = EK[3] ^ P[3];
        P+=4;
        C+=4;
        // CTR[3] = bswap_32(bswap_32(CTR[3]) + 1);
		CTR[0] = ((CTR[0] +1) & (0xFFFFFFFF));
    }
    if(i*16 < mlen)
    {
        AES_256_Encrypt(EK, CTR, ks);
        // CTR[3] = bswap_32(bswap_32(CTR[3]) + 1);
        CTR[0] = CTR[0] +1;
		for(i*=16; i<mlen; i++)
        {
            out[i] = ((uint8_t*)EK)[i%16] ^ in[i];
        }
    }
}

void gfmul_int(uint64_t* a, uint64_t* b, uint64_t* res){  
    uint64_t tmp1[2], tmp2[2], tmp3[2], tmp4[2];
	uint64_t XMMMASK[2] = {0x1, 0xc200000000000000};

    vclmul_emulator(a,b,tmp1,0x00);
    vclmul_emulator(a,b,tmp3,0x10);
    vclmul_emulator(a,b,tmp2,0x01);
    vclmul_emulator(a,b,tmp4,0x11);
	
	tmp2[0] ^= tmp3[0];
	tmp2[1] ^= tmp3[1];

	tmp3[0] = 0;
	tmp3[1] = tmp2[0];
    
	tmp2[0] = tmp2[1];
	tmp2[1] = 0;
	
	tmp1[0] ^= tmp3[0];
	tmp1[1] ^= tmp3[1];
	
	tmp4[0] ^= tmp2[0];
	tmp4[1] ^= tmp2[1];
	
    vclmul_emulator(XMMMASK,tmp1,tmp2,0x01);
	memcpy((uint32_t*)tmp3,  (uint32_t*)tmp1+2,4);
	memcpy((uint32_t*)tmp3+1,(uint32_t*)tmp1+3,4);
	memcpy((uint32_t*)tmp3+2,(uint32_t*)tmp1  ,4);
	memcpy((uint32_t*)tmp3+3,(uint32_t*)tmp1+1,4);
	
	tmp1[0] = tmp2[0] ^ tmp3[0];
	tmp1[1] = tmp2[1] ^ tmp3[1];

    vclmul_emulator(XMMMASK,tmp1,tmp2,0x01);
    memcpy((uint32_t*)tmp3,  (uint32_t*)tmp1+2,4);
	memcpy((uint32_t*)tmp3+1,(uint32_t*)tmp1+3,4);
	memcpy((uint32_t*)tmp3+2,(uint32_t*)tmp1  ,4);
	memcpy((uint32_t*)tmp3+3,(uint32_t*)tmp1+1,4);
	
	tmp1[0] = tmp2[0] ^ tmp3[0];
	tmp1[1] = tmp2[1] ^ tmp3[1];
	
	res[0] = tmp4[0] ^ tmp1[0];
	res[1] = tmp4[1] ^ tmp1[1];
}

void POLYVAL(uint64_t* input, uint64_t* H, uint64_t len, uint64_t* result)
{	
    
	ALIGN16 
	uint64_t current_res[2];
	uint64_t in[2];
	current_res[0] = result[0];
    current_res[1] = result[1];

	int i;
	int blocks = (int)(len/16);
	if (blocks == 0) return;
	
	for (i = 0; i < blocks; i++) {
		//XOR with buffer
		in[0] = input[2*i];
        in[1] = input[2*i+1];
		
		current_res[0] ^= in[0];
		current_res[1] ^= in[1];
		gfmul_int(current_res, H, current_res);
	}
	result[0] = current_res[0];
	result[1] = current_res[1];
}