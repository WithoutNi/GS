#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>

#include "../FSDGS/func.h"
#include "cycles.h"

#define SPX_MLEN SPX_N
#define NTESTS 1000
#define LAYER 0
#define SIG_BYTES (2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 3) * SPX_N + 2 * (SPX_WOTS_BYTES + COUNTER_SIZE) + AUTH_BYTES)

unsigned char Auth_opk_ID[lr][2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2) * SPX_N + SPX_WOTS_BYTES + COUNTER_SIZE + AUTH_BYTES] = {0};

int AE_Verify(const unsigned char* m1,const unsigned char*m);
void NJoin(MoMST *MMT[lr], struct GM *GM1, struct Mem *Mem1, unsigned char RF_ID[lr][SPX_N], long T,
           PunPRF *Fp[SPX_D + 1], struct MMT_Sig *Sig_sMI_GM[lr], unsigned char cache[SPX_D][KEY_SIZE * LEAF_NUM]);
void NSign(unsigned char *SIG, unsigned char *sk_ID, struct state_ID *st_ID, long T, const unsigned char *m, uint32_t mlen);

static int cmp_llu(const void *a, const void *b)
{
    if (*(unsigned long long *)a < *(unsigned long long *)b)
        return -1;
    if (*(unsigned long long *)a > *(unsigned long long *)b)
        return 1;
    return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen)
{
    qsort(l, llen, sizeof(unsigned long long), cmp_llu);

    if (llen % 2)
        return l[llen / 2];
    else
        return (l[llen / 2 - 1] + l[llen / 2]) / 2;
}

static void delta(unsigned long long *l, size_t llen)
{
    unsigned int i;
    for (i = 0; i < llen - 1; i++)
    {
        l[i] = l[i + 1] - l[i];
    }
}

static void printfcomma(unsigned long long n)
{
    if (n < 1000)
    {
        printf("%llu", n);
        return;
    }
    printfcomma(n / 1000);
    printf(",%03llu", n % 1000);
}

static void printfalignedcomma(unsigned long long n, int len)
{
    unsigned long long ncopy = n;
    int i = 0;

    while (ncopy > 9)
    {
        len -= 1;
        ncopy /= 10;
        i += 1; // to account for commas
    }
    i = i / 3 - 1; // to account for commas
    for (; i < len; i++)
    {
        printf(" ");
    }
    printfcomma(n);
}

static void display_result(double result, unsigned long long *l, size_t llen, unsigned long long mul)
{
    unsigned long long med;

    result /= NTESTS;
    delta(l, NTESTS + 1);
    med = median(l, llen);
    printf("avg. %11.2lf us (%6.2lf ms); median ", result, result / 1e3);
    printfalignedcomma(med, 12);
    printf(" cycles,  %5llux: ", mul);
    printfalignedcomma(mul * med, 12);
    printf(" cycles\n");
}

static void save_result(FILE *fp, const char *preamble, unsigned long long *l, size_t llen)
{
    size_t i;

    fprintf(fp, "%s", preamble);
    for (i = 0; i < llen; i++)
        fprintf(fp, " %llu ", l[i]);
    fprintf(fp, "\n");
}

#define MEASURE_GENERIC(TEXT, MUL, FNCALL, CORR)                                                                         \
    printf(TEXT);                                                                                                        \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);                                                                     \
    for (i = 0; i < NTESTS; i++)                                                                                         \
    {                                                                                                                    \
        t[i] = cpucycles() / CORR;                                                                                       \
        FNCALL;                                                                                                          \
    }                                                                                                                    \
    t[NTESTS] = cpucycles();                                                                                             \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);                                                                      \
    result = ((double)(stop.tv_sec - start.tv_sec) * 1e6 + (double)(stop.tv_nsec - start.tv_nsec) / 1e3) / (double)CORR; \
    display_result(result, t, NTESTS, MUL);
#define MEASURT(TEXT, MUL, FNCALL)         \
    MEASURE_GENERIC(                       \
        TEXT, MUL,                         \
        do {                               \
            for (int j = 0; j < 1000; j++) \
            {                              \
                FNCALL;                    \
            }                              \
        } while (0);                       \
        ,                                  \
        1000);
#define MEASURE(TEXT, MUL, FNCALL) MEASURE_GENERIC(TEXT, MUL, FNCALL, 1)

int main()
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);
    init_cpucycles();

    spx_ctx ctx1;
    unsigned char block[SPX_N];
    unsigned char addr2[SPX_ADDR_BYTES];

    PunPRF *Fp[SPX_D + 1];
    int k = SPX_N * 128;
    int SP[2] = {SPX_FULL_HEIGHT, SPX_D};
    struct GM *GM1;

    unsigned char ID[ID_SIZE] = {'I', 'D', '1'};
    struct Mem *Mem1;

    unsigned char RF_ID[lr][SPX_N];

    long T = 0;
    struct MMT_Sig *Sig_sMI_GM[lr];
    struct MMT_Sig *p = (struct MMT_Sig *)malloc(lr * sizeof(struct MMT_Sig));
    for (int i = 0; i < lr; i++)
    {
        Sig_sMI_GM[i] = p + i;
    }
    MoMST *MMT[lr];
    unsigned char cache[SPX_D][KEY_SIZE * LEAF_NUM] = {0};

    unsigned char SIG[SIG_BYTES] = {0};
    uint32_t mlen = 100;
    unsigned char *m = (unsigned char *)calloc(mlen, sizeof(unsigned char));
    randombytes(m, mlen);

    unsigned char ciphertext[CIPHERTEXT_SIZE]={0};
    unsigned char m1[CIPHERTEXT_SIZE];
    uint8_t TAG[16]={0};
    uint8_t* AAD=NULL;
    uint8_t key[32]={0};
    uint8_t nonce[16]={0};
    randombytes(key,32);
    randombytes(nonce,16);
    AES_GCM_SIV* E=new AES_GCM_SIV(key,nonce);

    unsigned char *ID1;

    unsigned long long t[NTESTS + 1];
    struct timespec start, stop;
    double result;
    unsigned int i;

    FILE *fp;
    char filename[100];
#define str(s) #s
#define xstr(s) str(s)

    printf("%s\n", xstr(PARAMS));

    printf("Parameters: n = %d, h = %d, d = %d, w = %d,  size = %d\n",
           SPX_N, SPX_FULL_HEIGHT, SPX_D,
           SPX_WOTS_W, SIG_BYTES);
    sprintf(filename, "%s", xstr(PARAMS));

    fp = fopen(filename, "w+");
    fprintf(fp, "n= %d h = %d d= %d w= %d size= %d\n",
            SPX_N, SPX_FULL_HEIGHT, SPX_D,
            SPX_WOTS_W, SIG_BYTES);
    printf("Running %d iterations.\n", NTESTS);

    /*AE performance*/
    MEASURE("AE.Enc..   ",1, E->Enc(ciphertext,TAG,AAD,m,0,CIPHERTEXT_SIZE));
    save_result(fp,"AE.Enc",t,NTESTS);
    MEASURE("AE.Dec..   ",1,E->Dec(m1,TAG,AAD,ciphertext,0,CIPHERTEXT_SIZE));
    save_result(fp,"AE.Dec",t,NTESTS);
    printf("AE_verify=%d\n",AE_Verify(m1,m));

    /*PFSGS performance*/
    MEASURE("hash..     ", 1, thash(block, block, 1, &ctx1, (uint32_t *)addr2));
    save_result(fp, "thash", t, NTESTS);
    MEASURE("GMInit..   ", 1, GM1 = GMInit(k, SP, Fp));
    save_result(fp, "GMinit", t, NTESTS);
    MEASURE("MInit..    ", 1, Mem1 = MInit(ID));
    save_result(fp, "MInit", t, NTESTS);
    MEASURE("MRegGen..  ", 1, MRegGen(Mem1->sk_ID, RF_ID));
    save_result(fp, "MRegGen", t, NTESTS);
    MEASURE("Join..     ", 1, NJoin(MMT, GM1, Mem1, RF_ID, T, Fp, Sig_sMI_GM, cache));
    save_result(fp, "Join", t, NTESTS);
    uint32_t sMI = Sig_sMI_GM[0]->wots_sign_leaf;
    uint64_t sTI = MMT[0]->sTI;
    MEASURE("Sign..     ", 1, NSign(SIG, Mem1->sk_ID, &(Mem1->st_ID), T, m, mlen));
    save_result(fp, "Sign", t, NTESTS);
    MEASURE("Verify..   ", 1, Verify(GM1, m, mlen, sTI, sMI, SIG, T));
    save_result(fp, "Verify", t, NTESTS);
    printf("SIG Verify=%d\n", Verify(GM1, m, mlen, sTI, sMI, SIG, T));
    MEASURE("Open..     ", 1, ID1 = Open(GM1, m, mlen, sTI, sMI, SIG, T));
    save_result(fp, "Open", t, NTESTS);

    unsigned char *RSS = (unsigned char *)malloc(2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2 + 1) * SPX_N + 2 * (SPX_WOTS_BYTES + COUNTER_SIZE) + AUTH_BYTES + mlen + 8);
    memcpy(RSS, SIG, 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2 + 1) * SPX_N + 2 * (SPX_WOTS_BYTES + COUNTER_SIZE) + AUTH_BYTES);
    memcpy(RSS + 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2 + 1) * SPX_N + 2 * (SPX_WOTS_BYTES + COUNTER_SIZE) + AUTH_BYTES, m, mlen);
    unsigned char time_bytes[8] = {0};
    ull_to_bytes(time_bytes, 8, T);
    memcpy(RSS + 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2 + 1) * SPX_N + 2 * (SPX_WOTS_BYTES + COUNTER_SIZE) + AUTH_BYTES + mlen, time_bytes, 8);
    MEASURE("Revoke..   ", 1, Revoke(GM1, Mem1->ID, RSS, mlen, sTI, sMI, T));
    save_result(fp, "Revoke", t, NTESTS);
    printf("Revoke then Verify=%d\n", Verify(GM1, m, mlen, sTI, sMI, SIG, T));

    fprintf(fp, "Size %d\n", SIG_BYTES);

    printf("Signature size: %d (%.2f KiB)\n", SIG_BYTES, SIG_BYTES / 1024.0);

    free(m);
    free(p);
    free(GM1);
    free(Mem1);
    for (int i = 0; i < lr; i++)
    {
        free(MMT[i]);
    }
    free(ID1);
    free(RSS);

    fclose(fp);

    return 0;
}

int AE_Verify(const unsigned char* m1,const unsigned char*m)
{
    int re=1;
    if(memcmp(m1,m,CIPHERTEXT_SIZE)){
        re=0;
    }
    return re;
}

void NJoin(MoMST *MMT[lr], struct GM *GM1, struct Mem *Mem1, unsigned char RF_ID[lr][SPX_N], long T,
           PunPRF *Fp[SPX_D + 1], struct MMT_Sig *Sig_sMI_GM[lr], unsigned char cache[SPX_D][KEY_SIZE * LEAF_NUM])
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
    }
}

void NSign(unsigned char *SIG, unsigned char *sk_ID, struct state_ID *st_ID, long T, const unsigned char *m, uint32_t mlen)
{
    (void)T;
    unsigned char sd_ID[KEY_SIZE];
    memcpy(sd_ID, sk_ID, KEY_SIZE);
    PRG *G1 = new PRG(sd_ID);
    unsigned char out[2][KEY_SIZE];
    G1->Eval(out);
     unsigned char sdvID[KEY_SIZE];
    memcpy(sdvID, out[0], KEY_SIZE);

    spx_ctx ctx;
    memset(&ctx, 0, sizeof(spx_ctx));
    struct leaf_info_x1 leaf;
    unsigned char addr[SPX_ADDR_BYTES] = {0};
    // randombytes(addr, SPX_ADDR_BYTES); // random select a address
    unsigned steps[SPX_WOTS_LEN] = {0};
    INITIALIZE_LEAF_INFO_X1(leaf, addr, steps);
    set_type(&(leaf.pk_addr[0]), SPX_ADDR_TYPE_WOTSPK);
    unsigned char OPK_ID[SPX_N] = {0};
    unsigned char rs_ID[KEY_SIZE];
    uint32_t counter;
    unsigned char sig[SPX_WOTS_BYTES + COUNTER_SIZE] = {0};

    for (int j = 0; j < lr; j++)
    {
        G1->Update(out[1]);
        G1->Eval(out);
        memcpy(rs_ID, out[0], KEY_SIZE);
        OTS_KGen(OPK_ID, &ctx, 0, &leaf, rs_ID);
        if (memcmp(OPK_ID, st_ID->OPK_ID[0], SPX_N) == 0)
        {
            // printf("opkID belongs to the member sub-layer\n");
            OTS_Sign(sig, m, mlen, &ctx, 0, &leaf, &counter, rs_ID);
            unsigned char counter_bytes[COUNTER_SIZE];
            ull_to_bytes(counter_bytes, COUNTER_SIZE, counter);
            memcpy(sig + SPX_WOTS_BYTES, counter_bytes, COUNTER_SIZE);
            memcpy(SIG + SPX_N + 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2) * SPX_N + SPX_WOTS_BYTES + COUNTER_SIZE + AUTH_BYTES, sig, SPX_WOTS_BYTES + COUNTER_SIZE);
            unsigned char OPK1[SPX_N] = {0};
            OTS_PK_From_Sig(OPK1, sig, m, mlen, &ctx, 0, &leaf, counter);
            if (memcmp(OPK1, OPK_ID, SPX_N) == 0)
            {
                // printf("Sign..verify=1\n");
                memcpy(SIG, OPK_ID, SPX_N);
                memcpy(SIG + SPX_N, st_ID->Auth[0], 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2) * SPX_N + SPX_WOTS_BYTES + COUNTER_SIZE + AUTH_BYTES);
                break;
            }
        }
        if (j == (lr - 1))
        {
            /*update the secret key sk_ID*/
            memcpy(sk_ID, sdvID, KEY_SIZE);
            printf("opkID doesn't belong to the member sub-layer\n");
            unsigned char rs_ID1[KEY_SIZE];
            unsigned char OPK_ID1[SPX_N] = {0};
            memcpy(rs_ID1, out[1], KEY_SIZE);
            OTS_KGen(OPK_ID1, &ctx, 0, &leaf, rs_ID1);

            /*compute the c'ID*/
            unsigned char cID1[CIPHERTEXT_SIZE + 16] = {0}; // cID1=ciphertext2 || TAG
            unsigned char ciphertext[CIPHERTEXT_SIZE] = {0};
            unsigned char ID[ID_SIZE] = {'I', 'D', '1'};
            unsigned char ke1[32] = {0};
            unsigned char re1[16] = {0};
            uint8_t TAG[16] = {0};
            uint8_t *AAD = NULL;
            randombytes(ke1, 32);
            randombytes(re1, 16);
            AES_GCM_SIV *E = new AES_GCM_SIV(ke1, re1);
            E->Enc(ciphertext, TAG, AAD, ID, 0, CIPHERTEXT_SIZE);
            memcpy(cID1, ciphertext, CIPHERTEXT_SIZE);
            memcpy(cID1 + CIPHERTEXT_SIZE, TAG, 16);

            unsigned char OPK_ID1_and_cID1[SPX_N + AES_GCM_CIPHERTEXT_SIZE] = {0}; // M=(OPK_ID1 || cID1)
            memcpy(OPK_ID1_and_cID1, OPK_ID1, SPX_N);
            memcpy(OPK_ID1_and_cID1 + SPX_N, cID1, AES_GCM_CIPHERTEXT_SIZE);

            /*σID := S.Sign(oskID , opk_ID1 ||cID1 )*/
            unsigned char sig1[SPX_WOTS_BYTES + COUNTER_SIZE] = {0};
            uint32_t counter1;
            OTS_Sign(sig1, OPK_ID1_and_cID1, SPX_N + AES_GCM_CIPHERTEXT_SIZE, &ctx, 0, &leaf, &counter1, rs_ID);
            unsigned char counter1_bytes[COUNTER_SIZE] = {0};
            ull_to_bytes(counter1_bytes, COUNTER_SIZE, counter1);
            memcpy(sig1 + SPX_WOTS_BYTES, counter1_bytes, COUNTER_SIZE);

            unsigned char OPK2[SPX_N] = {0};
            OTS_PK_From_Sig(OPK2, sig1, OPK_ID1_and_cID1, SPX_N + AES_GCM_CIPHERTEXT_SIZE, &ctx, 0, &leaf, counter1);
            if (memcmp(OPK2, OPK_ID1, SPX_N) == 0)
            {
                printf("(OPK_ID1 || cID1) wots verify sucess\n");
                memcpy(SIG, OPK_ID1, SPX_N);
                memcpy(SIG + 2 * SPX_N + AES_GCM_CIPHERTEXT_SIZE, cID1, AES_GCM_CIPHERTEXT_SIZE);
                memcpy(SIG + (SPX_TREE_HEIGHT + 2) * SPX_N + 2 * AES_GCM_CIPHERTEXT_SIZE, sig1, SPX_WOTS_BYTES + COUNTER_SIZE);
            }

            OTS_Sign(sig, m, mlen, &ctx, 0, &leaf, &counter, rs_ID1);
            unsigned char counter_bytes[COUNTER_SIZE];
            ull_to_bytes(counter_bytes, COUNTER_SIZE, counter);
            memcpy(sig + SPX_WOTS_BYTES, counter_bytes, COUNTER_SIZE);
            memcpy(SIG + SPX_N, st_ID->OPK_ID[0], SPX_N);
            memcpy(SIG + 2 * SPX_N, st_ID->Auth[0] + SPX_N, AES_GCM_CIPHERTEXT_SIZE);
            memcpy(SIG + 2 * SPX_N + 2 * AES_GCM_CIPHERTEXT_SIZE, st_ID->Auth[0] + SPX_N + 2 * AES_GCM_CIPHERTEXT_SIZE, SPX_TREE_HEIGHT * SPX_N);
            memcpy(SIG + (SPX_TREE_HEIGHT + 2) * SPX_N + 2 * AES_GCM_CIPHERTEXT_SIZE + SPX_WOTS_BYTES + COUNTER_SIZE, st_ID->Auth[0] + (SPX_TREE_HEIGHT + 1) * SPX_N + 2 * AES_GCM_CIPHERTEXT_SIZE + SPX_WOTS_BYTES + COUNTER_SIZE, SPX_N + AUTH_BYTES);
            memcpy(SIG + SPX_N + 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2) * SPX_N + SPX_WOTS_BYTES + COUNTER_SIZE + AUTH_BYTES, sig, SPX_WOTS_BYTES + COUNTER_SIZE);
        }
    }
}