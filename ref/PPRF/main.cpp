#include "PunPRF.h"
#include "../utils.h"
int main()
{
    const unsigned char *seed = (const unsigned char *)"061550234D158C5EC95595FE04EF7A25";
    // uint32_t layer = 0;
    uint64_t leaf_idx = 3;
    PunPRF *PunPRF1=new PunPRF(seed, (uint32_t)0);

    PunPRF1->Punc(leaf_idx, 4);
    // PunPRF1->Punc(leaf_idx-1,4);
    // PunPRF1->Punc(leaf_idx+1,4);
    unsigned char *result = PunPRF1->Eval(leaf_idx, 4);
    if (result)
    {
        for (int i = 0; i < KEY_SIZE; i++)
        {
            printf("%02x", result[i]);
        }
        printf("\n");
        free(result);
    }
    unsigned char kpi[KEY_SIZE]={0};
    unsigned char *result2 = new unsigned char[KEY_SIZE];
    result2 = PunPRF1->GetMsg(kpi, leaf_idx+1, 4);
    printf("result2\n");
    for (int i = 0; i < KEY_SIZE; i++)
    {
        printf("%x", result2[i]);
    }
    printf("\n");
    // unsigned long long ull=bytes_to_ull(result2,KEY_SIZE);
    // printf("ull=%llu\n",ull);
    free(result2);

    return 0;

}