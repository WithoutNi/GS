# include "AES_GCM_SIV.h"
# include "../randombytes.h"

int main(){
    uint8_t *m=(unsigned char*)"0123456789abcdef0123456789abcdef";
    unsigned char ciphertext[M_SIZE]={0};
    unsigned char m1[M_SIZE];
    uint8_t TAG[16]={0};
    uint8_t* AAD=NULL;
    uint8_t key[32]={0};
    uint8_t nonce[16]={0};
    randombytes(key,32);
    randombytes(nonce,16);
    AES_GCM_SIV* E=new AES_GCM_SIV(key,nonce);
    E->Enc(ciphertext,TAG,AAD,m,0,M_SIZE);
    printf("ciphertext:\n");
    for(int j=0;j<M_SIZE;j++){
        printf("%02x ",ciphertext[j]);
    }
    printf("\n");
    E->Dec(m1,TAG,AAD,ciphertext,0,M_SIZE);
    printf("msg:\n");
    for(int j=0;j<M_SIZE;j++){
        printf("%02x ",m1[j]);
    }
    printf("\n");
    if(memcmp(m,m1,M_SIZE)==0){
        printf("sucess\n");
    }
    else{
        printf("failure\n");
    }


    return 0;

}