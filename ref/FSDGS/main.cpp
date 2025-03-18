#include "func.h"
#include <stdio.h>

void fprintBstr(FILE *fp, const char *S, unsigned char *A, unsigned long long L);
void Join(MoMST *MMT[lr], struct GM *GM1, struct Mem *Mem1, unsigned char RF_ID[lr][SPX_N], long T,
          PunPRF *Fp[SPX_D + 1], struct MMT_Sig *Sig_sMI_GM[lr], unsigned char cache[SPX_D][KEY_SIZE * LEAF_NUM], FILE *file1, FILE *file2);
unsigned char Auth_opk_ID[lr][2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2) * SPX_N + SPX_WOTS_BYTES + COUNTER_SIZE + AUTH_BYTES] = {0};
int main()
{
    char file1name[32], file2name[32];
    unsigned char cache[SPX_D][KEY_SIZE * LEAF_NUM] = {0};
    FILE *file1, *file2, *file3;
    sprintf(file1name, "FSDGS_%d.rsp", SPX_N * 8);
    if ((file1 = fopen(file1name, "w")) == NULL)
    {
        printf("Couldn't open <%s> for write\n", file1name);
        return -1;
    }
    sprintf(file2name, "Vt");
    if ((file2 = fopen(file2name, "w")) == NULL)
    {
        printf("Couldn't open <%s> for write\n", file2name);
        return -1;
    }
    if ((file3 = fopen("Vt2", "w")) == NULL)
    {
        printf("Couldn't open file3 for write\n");
        return -1;
    }

    PunPRF *Fp[SPX_D + 1];
    /*GMInit*/
    int k = SPX_N * 128;
    int SP[2] = {SPX_FULL_HEIGHT, SPX_D};
    struct GM *GM1 = GMInit(k, SP, Fp);

    fprintBstr(file1, "kpi = ", GM1->sk_GM, (SPX_D + 1) * KEY_SIZE);
    fprintBstr(file1, "k_GM = ", GM1->sk_GM + (SPX_D + 1) * KEY_SIZE, CRYPTO_SEEDBYTES);
    fprintBstr(file1, "gpk = ", GM1->gpk, SPX_N);

    /*MInit*/
    unsigned char ID[ID_SIZE] = {'I', 'D', '1'};
    struct Mem *Mem1 = MInit(ID);
    // printf("ID ");
    // for (int i = 0; i < ID_SIZE; i++)
    // {
    //     printf("%c", Mem1->ID[i]);
    // }
    // printf("\n");
    // printf("sk_ID ");
    // for (int i = 0; i < KEY_SIZE; i++)
    // {
    //     printf("%02x ", Mem1->sk_ID[i]);
    // }
    // printf("\n");

    /*MRegGen*/
    unsigned char RF_ID[lr][SPX_N];
    MRegGen(Mem1->sk_ID, RF_ID);

    unsigned char ID2[ID_SIZE] = {'I', 'D', '2'};
    struct Mem *Mem2 = MInit(ID2);
    unsigned char RF_ID2[lr][SPX_N];
    MRegGen(Mem2->sk_ID, RF_ID2);

    /*Join*/
    long T = 0;
    struct MMT_Sig *Sig_sMI_GM[lr];
    struct MMT_Sig *p = (struct MMT_Sig *)malloc(lr * sizeof(struct MMT_Sig));
    for (int i = 0; i < lr; i++)
    {
        Sig_sMI_GM[i] = p + i;
    }
    MoMST *MMT[lr];
    Join(MMT, GM1, Mem1, RF_ID, T, Fp, Sig_sMI_GM, cache, file1,file2);
    Join(MMT, GM1, Mem2, RF_ID2, T, Fp, Sig_sMI_GM, cache, file1,file2);
    uint32_t sMI = Sig_sMI_GM[0]->wots_sign_leaf;
    uint64_t sTI = MMT[0]->sTI;
    unsigned char SIG[2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 3) * SPX_N + 2 * (SPX_WOTS_BYTES + COUNTER_SIZE) + AUTH_BYTES] = {0};
    uint32_t mlen = 100;
    unsigned char *m = (unsigned char *)calloc(mlen, sizeof(unsigned char));
    randombytes(m, mlen);

    /*Sign*/
    Sign(SIG, Mem2->sk_ID, &(Mem2->st_ID), T, m, mlen);
    fprintf(file1, "mlen =%u\n", mlen);
    fprintBstr(file1, "m = ", m, mlen);
    fprintf(file1, "SIGlen =%u\n", 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2 + 1) * SPX_N + 2 * (SPX_WOTS_BYTES + COUNTER_SIZE) + AUTH_BYTES);
    fprintBstr(file1, "SIG = ", SIG, 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2 + 1) * SPX_N + 2 * (SPX_WOTS_BYTES + COUNTER_SIZE) + AUTH_BYTES);

    /*first Verify*/
    printf("SIG Verify=%d\n", Verify(GM1, m, mlen, sTI, sMI, SIG, T));

    /*second Verify*/
    // uint32_t leaf1_idx = Sig_sMI_GM[1]->wots_sign_leaf;
    // uint64_t tree1_idx = MMT[1]->sTI;
    // unsigned char SIG1[2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 3) * SPX_N + 2 * (SPX_WOTS_BYTES + COUNTER_SIZE) + AUTH_BYTES] = {0};
    // Sign(SIG1, Mem2->sk_ID, &(Mem2->st_ID), T, m, mlen);
    // fprintf(file1, "SIGlen =%u\n", 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2 + 1) * SPX_N + 2 * (SPX_WOTS_BYTES + COUNTER_SIZE) + AUTH_BYTES);
    // fprintBstr(file1, "SIG1 = ", SIG1, 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2 + 1) * SPX_N + 2 * (SPX_WOTS_BYTES + COUNTER_SIZE) + AUTH_BYTES);
    // printf("SIG1 Verify=%d\n", Verify(GM1, m, mlen, tree1_idx, leaf1_idx, SIG1, T));

    /*third Verify*/
    // uint32_t leaf2_idx = Sig_sMI_GM[2]->wots_sign_leaf;
    // uint64_t tree2_idx = MMT[2]->sTI;
    // unsigned char SIG2[2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 3) * SPX_N + 2 * (SPX_WOTS_BYTES + COUNTER_SIZE) + AUTH_BYTES] = {0};
    // Sign(SIG2, Mem2->sk_ID, &(Mem2->st_ID), T, m, mlen);
    // fprintf(file1, "SIGlen =%u\n", 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2 + 1) * SPX_N + 2 * (SPX_WOTS_BYTES + COUNTER_SIZE) + AUTH_BYTES);
    // fprintBstr(file1, "SIG2 = ", SIG2, 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2 + 1) * SPX_N + 2 * (SPX_WOTS_BYTES + COUNTER_SIZE) + AUTH_BYTES);
    // printf("SIG2 Verify=%d\n", Verify(GM1, m, mlen, tree2_idx, leaf2_idx, SIG2, T));

    /*Open*/
    unsigned char *ID1 = Open(GM1, m, mlen, sTI, sMI, SIG, T);
    if (ID1 != NULL)
    {
        printf("Open ID = ");
        for (int j = 0; j < ID_SIZE; j++)
        {
            printf("%c", ID1[j]);
        }
        printf("\n");
    }

    /*Revoke*/
    unsigned char *RSS = (unsigned char *)malloc(2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2 + 1) * SPX_N + 2 * (SPX_WOTS_BYTES + COUNTER_SIZE) + AUTH_BYTES + mlen + 8);
    memcpy(RSS, SIG, 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2 + 1) * SPX_N + 2 * (SPX_WOTS_BYTES + COUNTER_SIZE) + AUTH_BYTES);
    memcpy(RSS + 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2 + 1) * SPX_N + 2 * (SPX_WOTS_BYTES + COUNTER_SIZE) + AUTH_BYTES, m, mlen);
    unsigned char time_bytes[8] = {0};
    ull_to_bytes(time_bytes, 8, T);
    memcpy(RSS + 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2 + 1) * SPX_N + 2 * (SPX_WOTS_BYTES + COUNTER_SIZE) + AUTH_BYTES + mlen, time_bytes, 8);
    Revoke(GM1, Mem2->ID, RSS, mlen, sTI, sMI, T);
    printf("Revoke then Verify=%d\n", Verify(GM1, m, mlen, sTI, sMI, SIG, T));

    printf("st_GM RegIDL\n");
    for (int j = 0; j < MAX_MEMBER; j++)
    {
        for (int i = 0; i < ID_SIZE; i++)
        {
            printf("%c", GM1->st_GM.RegIDL[j][i]);
        }
        printf("\n");
    }
    printf("st_GM RL\n");
    for (int j = 0; j < MAX_MEMBER; j++)
    {
        for (int k = 0; k < AES_GCM_CIPHERTEXT_SIZE; k++)
        {
            printf("%02x", GM1->st_GM.RL[j][k]);
        }
        printf("\n");
    }

    for (int j = 0; j < lr; j++)
    {
        if (Mem2->st_ID.Auth[j] != NULL)
        {
            fprintf(file3, "%d-th ", j);
            fprintBstr(file3, "OPK_ID = ", Mem2->st_ID.OPK_ID[j], SPX_N);
            fprintBstr(file3, "Auth[OPK_ID] = ", Mem2->st_ID.Auth[j], 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2) * SPX_N + SPX_WOTS_BYTES + COUNTER_SIZE + AUTH_BYTES);
            fprintf(file3, "\n");
        }
    }

    free(m);
    free(GM1);
    free(Mem1);
    free(Mem2);
    for (int i = 0; i < lr; i++)
    {
        free(MMT[i]);
    }
    free(p);
    free(ID1);
    free(RSS);

    fclose(file1);
    fclose(file2);
    fclose(file3);

    return 0;
}

void fprintBstr(FILE *fp, const char *S, unsigned char *A, unsigned long long L)
{
    unsigned long long i;

    fprintf(fp, "%s", S);

    for (i = 0; i < L; i++)
        fprintf(fp, "%02X", A[i]);

    if (L == 0)
        fprintf(fp, "00");

    fprintf(fp, "\n");
}

void Join(MoMST *MMT[lr], struct GM *GM1, struct Mem *Mem1, unsigned char RF_ID[lr][SPX_N], long T,
          PunPRF *Fp[SPX_D + 1], struct MMT_Sig *Sig_sMI_GM[lr], unsigned char cache[SPX_D][KEY_SIZE * LEAF_NUM], FILE *file1, FILE *file2)
{
    for (int i = 0; i < lr; i++)
    {
        MMT[i] = Join(GM1->sk_GM, &(GM1->st_GM), Mem1->ID, RF_ID[i], T, Fp, Sig_sMI_GM[i], cache);
        unsigned long long Authlen = GM1->st_GM.Authlen;
        uint32_t leaf_idx = Sig_sMI_GM[i]->wots_sign_leaf;
        memcpy(Auth_opk_ID[i], Sig_sMI_GM[i]->OPK_MI_GM, SPX_N);
        memcpy(Auth_opk_ID[i] + SPX_N, MMT[i]->leaves[leaf_idx].ciphertext1, AES_GCM_CIPHERTEXT_SIZE);
        memcpy(Auth_opk_ID[i] + SPX_N + AES_GCM_CIPHERTEXT_SIZE, MMT[i]->leaves[leaf_idx].ciphertext2, AES_GCM_CIPHERTEXT_SIZE);
        memcpy(Auth_opk_ID[i] + SPX_N + 2 * AES_GCM_CIPHERTEXT_SIZE, Sig_sMI_GM[i]->merkle_proof, SPX_TREE_HEIGHT * SPX_N);
        memcpy(Auth_opk_ID[i] + (SPX_TREE_HEIGHT + 1) * SPX_N + 2 * AES_GCM_CIPHERTEXT_SIZE, Sig_sMI_GM[i]->wots_sig, SPX_WOTS_BYTES + COUNTER_SIZE);
        memcpy(Auth_opk_ID[i] + (SPX_TREE_HEIGHT + 1) * SPX_N + 2 * AES_GCM_CIPHERTEXT_SIZE + SPX_WOTS_BYTES + COUNTER_SIZE, MMT[i]->Rt, SPX_N);
        memcpy(Auth_opk_ID[i] + (SPX_TREE_HEIGHT + 2) * SPX_N + 2 * AES_GCM_CIPHERTEXT_SIZE + SPX_WOTS_BYTES + COUNTER_SIZE, GM1->st_GM.Auth, Authlen);
        Mem1->RR_ID[i] = Auth_opk_ID[i];
        memcpy(Mem1->st_ID.OPK_ID[i], RF_ID[i], SPX_N);
        Mem1->st_ID.Auth[i] = Auth_opk_ID[i];
        fprintf(file1, "Auth[OPK_MI_ID]\n");
        fprintBstr(file1, "OPK_MI_GM = ", Sig_sMI_GM[i]->OPK_MI_GM, SPX_N);
        fprintBstr(file1, "c1MI = ", MMT[i]->leaves[leaf_idx].ciphertext1, AES_GCM_CIPHERTEXT_SIZE);
        fprintBstr(file1, "c2MI = ", MMT[i]->leaves[leaf_idx].ciphertext2, AES_GCM_CIPHERTEXT_SIZE);
        fprintBstr(file1, "pf_lf_sMI = ", Sig_sMI_GM[i]->merkle_proof, SPX_TREE_HEIGHT * SPX_N);
        fprintBstr(file1, "σsMI_GM = ", Sig_sMI_GM[i]->wots_sig, SPX_WOTS_BYTES + COUNTER_SIZE);
        fprintf(file1, "counter = %u\n", Sig_sMI_GM[i]->counter);
        fprintBstr(file1, "MMT[sTI].Rt = ", MMT[i]->Rt, SPX_N);
        fprintf(file1, "Authlen = %llu\n", Authlen);
        fprintBstr(file1, "Auth[MMT[sTI].Rt] = ", GM1->st_GM.Auth, Authlen);

        fprintf(file2, "%d-th ", i);
        fprintBstr(file2, "OPK_ID = ", Mem1->st_ID.OPK_ID[i], SPX_N);
        fprintBstr(file2, "Auth[OPK_ID] = ", Mem1->st_ID.Auth[i], 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2) * SPX_N + SPX_WOTS_BYTES + COUNTER_SIZE + AUTH_BYTES);
        fprintf(file2, "\n");
    }
}
