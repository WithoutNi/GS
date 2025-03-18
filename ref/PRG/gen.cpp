#include "prg.h"

int main()
{
    PRG *G = new PRG();
    unsigned char sdID[KEY_SIZE];
    G->getkey(sdID);
    printf("sdID ");
    for(int i=0;i<KEY_SIZE;i++){
        printf("%02x ",sdID[i]);
    }
    printf("\n");

    unsigned char sdID1[KEY_SIZE];
    PRG* G1=new PRG(sdID);
    G1->getkey(sdID1);
    printf("sdID1 ");
    for(int i=0;i<KEY_SIZE;i++){
        printf("%02x ",sdID1[i]);
    }
    printf("\n");

    unsigned char out[2][KEY_SIZE];
    for (int j = 0; j < 2; j++)
    {
        G->Eval(out);
        printf("%d-th out2 ",j);
        for (int k = 0; k < KEY_SIZE; k++)
        {
            printf("%02x ", out[1][k]);
        }
        printf("\n");
        G->Update(out[0]);
    }

    return 0;
}