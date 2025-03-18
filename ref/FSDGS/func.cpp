#include "func.h"

struct GM *GMInit(int k, int SP[2], PunPRF *Fp[SPX_D + 1])
{
    (void)k;
    (void)SP;

    struct GM *GM1 = (struct GM *)malloc(sizeof(struct GM));
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char seed[CRYPTO_SEEDBYTES];
    randombytes(seed, CRYPTO_SEEDBYTES);
    unsigned char kpi[KEY_SIZE];
    for (uint32_t j = 0; j < SPX_D + 1; j++)
    {
        Fp[j] = new PunPRF(seed, j);
        Fp[j]->getkey(kpi);
        memcpy((GM1->sk_GM) + j * KEY_SIZE, kpi, KEY_SIZE);
    }
    crypto_sign_seed_keypair(pk, sk, seed, Fp[SPX_D]);
    memcpy(GM1->sk_GM + (SPX_D + 1) * KEY_SIZE, sk, CRYPTO_SEEDBYTES);
    memcpy(GM1->gpk, pk + SPX_N, SPX_N);
    memset(GM1->st_GM.RegIDL, 0, MAX_MEMBER * ID_SIZE);
    memset(GM1->st_GM.RL, 0, MAX_MEMBER * AES_GCM_CIPHERTEXT_SIZE);
    GM1->st_GM.Auth = NULL;
    return GM1;
}

struct Mem *MInit(unsigned char ID[ID_SIZE])
{
    struct Mem *Mem1 = (struct Mem *)malloc(sizeof(struct Mem));
    memcpy(Mem1->ID, ID, ID_SIZE);
    PRG *G = new PRG();
    G->getkey(Mem1->sk_ID);
    return Mem1;
}

void MRegGen(unsigned char *sk_ID, unsigned char RF_ID[lr][SPX_N])
{
    unsigned char sd_ID[KEY_SIZE];
    memcpy(sd_ID, sk_ID, KEY_SIZE);
    PRG *G1 = new PRG(sd_ID);
    unsigned char out[2][KEY_SIZE];
    G1->Eval(out);
    unsigned char rs_ID[KEY_SIZE];

    // how to compute the opk when donit konw the index of used leaf
    spx_ctx ctx;
    memset(&ctx, 0, sizeof(spx_ctx));
    struct leaf_info_x1 leaf;
    unsigned char addr[SPX_ADDR_BYTES] = {0};
    // randombytes(addr, SPX_ADDR_BYTES); // random select a address
    unsigned steps[SPX_WOTS_LEN] = {0};
    INITIALIZE_LEAF_INFO_X1(leaf, addr, steps);
    set_type(&(leaf.pk_addr[0]), SPX_ADDR_TYPE_WOTSPK);
    unsigned char OPK_ID[SPX_N] = {0};
    for (int j = 0; j < lr; j++)
    {
        G1->Update(out[1]);
        G1->Eval(out);
        memcpy(rs_ID, out[0], KEY_SIZE);
        // printf("MRegGen rs_ID ");
        // for(int k=0;k<KEY_SIZE;k++){
        //     printf("%02x",rs_ID[k]);
        // }
        // printf("\n");
        OTS_KGen(OPK_ID, &ctx, 0, &leaf, rs_ID);
        memcpy(RF_ID[j], OPK_ID, SPX_N);
    }
}

struct MountIdx *RandSelect(unsigned char *sk_GM, unsigned char *ID, unsigned char OPK_ID[SPX_N], PunPRF *Fp0)
{
    unsigned char ks[KEY_SIZE] = {0};
    unsigned char *ch1 = (unsigned char *)"RandSel";
    spx_ctx ctx;
    memcpy(ctx.sk_seed, sk_GM + (SPX_D + 1) * KEY_SIZE, SPX_N);
    memcpy(ctx.pub_seed, sk_GM + (SPX_D + 1) * KEY_SIZE + 2 * SPX_N, SPX_N);
    initialize_hash_function(&ctx);
    F1(ks, KEY_SIZE, &ctx, ch1, (int)strlen((const char *)ch1));
    struct MountIdx *KI = (struct MountIdx *)malloc(sizeof(struct MountIdx));
    uint32_t ctr = 0;
    F2(&(KI->sTI), &(KI->sMI), ks, ID, OPK_ID, ctr);
    unsigned char *result = new unsigned char[KEY_SIZE];
    result = Fp0->Eval((unsigned long long)pow(2, SPX_TREE_HEIGHT) * KI->sTI + KI->sMI, (int)(SPX_FULL_HEIGHT + SPX_TREE_HEIGHT));
    while (result == NULL)
    {
        ctr++;
        F2(&(KI->sTI), &(KI->sMI), ks, ID, OPK_ID, ctr);
        result = Fp0->Eval((unsigned long long)pow(2, SPX_TREE_HEIGHT) * KI->sTI + KI->sMI, (int)(SPX_FULL_HEIGHT + SPX_TREE_HEIGHT));
    }
    return KI;
}

void mmt_gen_leaves(CacheElement lf[LEAF_NUM], struct RFCa *RFCa_MMT, uint32_t wots_addr[8], const spx_ctx *ctx, PunPRF *Fp0)
{
    struct leaf_info_x1 leaf;
    unsigned steps[SPX_WOTS_LEN] = {0};
    INITIALIZE_LEAF_INFO_X1(leaf, wots_addr, steps);
    set_type(&(leaf.pk_addr[0]), SPX_ADDR_TYPE_WOTSPK);
    unsigned char OPK[SPX_N] = {0};
    // unsigned char OPK_MI_GM[SPX_N] = {0};
    unsigned char *rs = new unsigned char[KEY_SIZE];
    for (uint32_t j = 0; j < LEAF_NUM; j++)
    {
        if (j == RFCa_MMT->MI.sMI)
        {
            memcpy(lf[j].OPK, RFCa_MMT->OPK_ID, SPX_N);
        }
        else
        {
            rs = Fp0->Eval((unsigned long long)pow(2, SPX_TREE_HEIGHT) * RFCa_MMT->MI.sTI + j, (int)(SPX_FULL_HEIGHT + SPX_TREE_HEIGHT));
            OTS_KGen(OPK, ctx, j, &leaf, rs);
            memcpy(lf[j].OPK, OPK, SPX_N);
        }
    }
    delete[] rs;

    // printf("OPK[16]\n");
    // for (uint32_t j = 0; j < LEAF_NUM; j++)
    // {
    //     for (int i = 0; i < SPX_N; i++)
    //     {
    //         printf("%02x", lf[j].OPK[i]);
    //     }
    //     printf("\n");
    // }
    // printf("OPK_MI_GM\n");
    // for (int i = 0; i < SPX_N; i++)
    // {
    //     printf("%02x", OPK_MI_GM[i]);
    // }
    // printf("\n");

    unsigned char cipher1[CIPHERTEXT_SIZE + 16] = {0}; // cipher1=ciphertext1 || TAG
    unsigned char ciphertext1[CIPHERTEXT_SIZE] = {0};
    unsigned char temp[SPX_N + CIPHERTEXT_SIZE + 16] = {0};
    unsigned char ch1[17] = {'K', '-', 'M', 'i', 'x'};
    unsigned char ch2[17] = {'R', '-', 'M', 'i', 'x'};
    unsigned char ke1MI[32] = {0};
    unsigned char re1MI[16] = {0};
    uint8_t TAG[16] = {0};
    uint8_t *AAD = NULL;
    uint64_t tree_idx = RFCa_MMT->MI.sTI;
    ull_to_bytes(ch1 + 5, 8, tree_idx);
    ull_to_bytes(ch2 + 5, 8, tree_idx);
    for (uint32_t i = 0; i < LEAF_NUM; i++)
    {
        lf[i].leaf_index = i;
        /*compute the first identity-OPK ciphertext(IOC)*/
        ull_to_bytes(ch1 + 13, 4, i);
        ull_to_bytes(ch2 + 13, 4, i);
        F1(ke1MI, 32, ctx, ch1, 17); // ke1MI := F1(kGM, “K-Mix” ||MI)  MI=(tree_idx || leaf_idx)
        F1(re1MI, 16, ctx, ch2, 17); // re1MI := F1(kGM, “R-Mix”||MI)
        AES_GCM_SIV *E = new AES_GCM_SIV(ke1MI, re1MI);

        /*record the currently used leaf's IOC*/
        if (i == RFCa_MMT->MI.sMI)
        {
            unsigned char ID[CIPHERTEXT_SIZE] = {0};
            memcpy(ID, RFCa_MMT->ID, CIPHERTEXT_SIZE);
            E->Enc(ciphertext1, TAG, AAD, ID, 0, CIPHERTEXT_SIZE);
        }
        else
        {
            unsigned char ID[CIPHERTEXT_SIZE] = {'G', 'M'};
            E->Enc(ciphertext1, TAG, AAD, ID, 0, CIPHERTEXT_SIZE);
        }
        memcpy(cipher1, ciphertext1, CIPHERTEXT_SIZE);
        memcpy(cipher1 + CIPHERTEXT_SIZE, TAG, 16);
        memcpy(lf[i].ciphertext1, cipher1, CIPHERTEXT_SIZE + 16);

        /*leaf=shake256(OPK || IOC1)*/
        memcpy(temp, lf[i].OPK, SPX_N);
        memcpy(temp + SPX_N, cipher1, CIPHERTEXT_SIZE + 16);
        shake256(lf[i].leaf_value, SPX_N, temp, SPX_N + CIPHERTEXT_SIZE + 16);
    }
}

void M_Build(MoMST *MMT_sTI, CacheElement lf[LEAF_NUM], const spx_ctx *ctx, uint32_t tree_addr[8])
{
    unsigned char current[2 * SPX_N];
    set_type(&tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    MMT_sTI->leaves = lf;
    for (int h = 0; h < SPX_TREE_HEIGHT; h++)
    {
        for (int j = 0; j < (1 << (SPX_TREE_HEIGHT - h - 1)); j++)
        {
            if (h == 0)
            {
                memcpy(&current[0], lf[2 * j].leaf_value, SPX_N);
                memcpy(&current[SPX_N], lf[2 * j + 1].leaf_value, SPX_N);
                set_tree_height(tree_addr, h + 1);
                set_tree_index(tree_addr, j);
                thash(&current[1 * SPX_N], &current[0 * SPX_N], 2, ctx, tree_addr);
                memcpy(MMT_sTI->inner_node[h][j], &current[SPX_N], SPX_N);
            }
            else
            {
                memcpy(&current[0], MMT_sTI->inner_node[h - 1][2 * j], SPX_N);
                memcpy(&current[SPX_N], MMT_sTI->inner_node[h - 1][2 * j + 1], SPX_N);
                set_tree_height(tree_addr, h + 1);
                set_tree_index(tree_addr, j);
                thash(&current[1 * SPX_N], &current[0 * SPX_N], 2, ctx, tree_addr);
                memcpy(MMT_sTI->inner_node[h][j], &current[SPX_N], SPX_N);
            }
        }
    }
    MMT_sTI->sTI = (uint64_t)bytes_to_ull((unsigned char *)tree_addr + SPX_OFFSET_TREE, 8);
    MMT_sTI->Rt = MMT_sTI->inner_node[SPX_TREE_HEIGHT - 1][0];
    // printf("MMT[sTI].Rt");
    // for(int i=0;i<SPX_N;i++){
    //     printf("%02x",MMT_sTI->Rt[i]);
    // }
    // printf("\n");
}

void M_GetPrf(unsigned char *pf_lf_sMI, MoMST *MMT_sTI, CacheElement *lf)
{
    uint32_t leaf_idx = lf->leaf_index;
    for (int j = 0; j < SPX_TREE_HEIGHT; j++)
    {
        int idx = (leaf_idx / (1 << j)) ^ 0x01;
        if (j == 0)
        {
            memcpy(pf_lf_sMI + j * SPX_N, MMT_sTI->leaves[idx].leaf_value, SPX_N);
        }
        else
        {
            memcpy(pf_lf_sMI + j * SPX_N, MMT_sTI->inner_node[j - 1][idx], SPX_N);
        }
    }
}

int M_Verify(const unsigned char *rt, CacheElement *lf, const unsigned char *pf_lf_sMI, const spx_ctx *ctx, uint32_t tree_addr[8])
{
    unsigned char root[SPX_N];
    uint32_t leaf_idx = lf->leaf_index;
    compute_root(root, lf->leaf_value, leaf_idx, 0, pf_lf_sMI, SPX_TREE_HEIGHT, ctx, tree_addr);
    if (memcmp(root, rt, SPX_N))
    {
        return 0;
    }
    return 1;
}

MoMST *Join(unsigned char *sk_GM, struct state_GM *st_GM, unsigned char *ID, unsigned char RF_ID[SPX_N], long T,
            PunPRF *Fp[SPX_D + 1], struct MMT_Sig *Sig_sMI_GM, unsigned char cache[SPX_D][KEY_SIZE * LEAF_NUM])
{
    (void)T;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    spx_ctx ctx;
    memcpy(ctx.sk_seed, sk_GM + (SPX_D + 1) * KEY_SIZE, SPX_N);
    memcpy(ctx.pub_seed, sk_GM + (SPX_D + 1) * KEY_SIZE + 2 * SPX_N, SPX_N);
    memcpy(sk, sk_GM + (SPX_D + 1) * KEY_SIZE, CRYPTO_SEEDBYTES);
    initialize_hash_function(&ctx);

    /*add the member ID to the RegIDL*/
    for (int j = 0; j < MAX_MEMBER; j++)
    {
        const char zero[ID_SIZE] = {0};
        if (strncmp((const char *)st_GM->RegIDL[j], (const char *)ID, ID_SIZE) == 0)
        { // ID has previously submitted a join request
            break;
        }
        if (strncmp((const char *)st_GM->RegIDL[j], zero, ID_SIZE) == 0)
        {
            memcpy(st_GM->RegIDL[j], ID, ID_SIZE);
            break;
        }
    }

    /*adds the tuple (ID, OPK_ID , MI) to a registration cache file RFCasTI  MMT*/
    struct RFCa *RFCa_MMT = (struct RFCa *)malloc(sizeof(struct RFCa));
    MoMST *MMT_sTI = (MoMST *)malloc(sizeof(MoMST));

    struct MountIdx *KI = RandSelect(sk_GM, ID, RF_ID, Fp[0]);
    memcpy(RFCa_MMT->ID, ID, ID_SIZE);
    memcpy(RFCa_MMT->OPK_ID, RF_ID, SPX_N);
    RFCa_MMT->MI.sTI = KI->sTI;
    RFCa_MMT->MI.sMI = KI->sMI;
    free(KI);

    // printf("MMT[sTI].sTI=%lu\n", RFCa_MMT->MI.sTI);
    // printf("MMT[sTI].sMI=%u\n", RFCa_MMT->MI.sMI);

    CacheElement *lf = (CacheElement *)malloc(LEAF_NUM * sizeof(CacheElement));
    unsigned char *newseed = new unsigned char[KEY_SIZE];
    newseed = Fp[1]->Eval((unsigned long long)(RFCa_MMT->MI.sTI), SPX_FULL_HEIGHT);
    unsigned char pf_lf_sMI[SPX_TREE_HEIGHT * SPX_N];

    /*Case 1 (Fp(kp, sTI) != ⊥) for MMT initialization*/
    if (newseed != NULL)
    {
        set_layer_addr(tree_addr, (uint32_t)0);
        set_tree_addr(tree_addr, RFCa_MMT->MI.sTI);
        copy_subtree_addr(wots_addr, tree_addr);

        mmt_gen_leaves(lf, RFCa_MMT, wots_addr, &ctx, Fp[0]);
        M_Build(MMT_sTI, lf, &ctx, tree_addr);
        M_GetPrf(pf_lf_sMI, MMT_sTI, &lf[RFCa_MMT->MI.sMI]);
        unsigned char *Auth = (unsigned char *)malloc(AUTH_BYTES);
        GetAuth(Auth, &st_GM->Authlen, Fp, sk, MMT_sTI->Rt, SPX_N, RFCa_MMT->MI.sTI, cache);
        st_GM->Auth = Auth;
    }

    /*Case 2 (Fp1(kp1, sTI) = ⊥) for MMT usage*/
    newseed = Fp[1]->Eval((unsigned long long)(RFCa_MMT->MI.sTI), SPX_FULL_HEIGHT);
    if (newseed == NULL)
    {
        /*compute the lf_sMI*/
        uint32_t wots_addr1[8] = {0};
        uint64_t tree_idx = RFCa_MMT->MI.sTI;
        uint32_t leaf_idx = RFCa_MMT->MI.sMI;
        set_layer_addr(wots_addr1, (uint32_t)0);
        set_tree_addr(wots_addr1, tree_idx);
        set_keypair_addr(wots_addr1, leaf_idx);
        struct leaf_info_x1 leaf1;
        unsigned steps[SPX_WOTS_LEN] = {0};
        INITIALIZE_LEAF_INFO_X1(leaf1, wots_addr1, steps);
        set_type(&(leaf1.pk_addr[0]), SPX_ADDR_TYPE_WOTSPK);
        unsigned char OPK_GM[SPX_N] = {0};
        unsigned char *rs_GM = new unsigned char[KEY_SIZE];
        rs_GM = Fp[0]->Eval((unsigned long long)pow(2, SPX_TREE_HEIGHT) * tree_idx + leaf_idx, (int)(SPX_FULL_HEIGHT + SPX_TREE_HEIGHT));
        OTS_KGen(OPK_GM, &ctx, leaf_idx, &leaf1, rs_GM);
        unsigned char temp[SPX_N + AES_GCM_CIPHERTEXT_SIZE] = {0};
        unsigned char lf_sMI[SPX_N] = {0};
        memcpy(temp, OPK_GM, SPX_N);
        memcpy(temp + SPX_N, MMT_sTI->leaves[leaf_idx].ciphertext1, AES_GCM_CIPHERTEXT_SIZE);
        shake256(lf_sMI, SPX_N, temp, SPX_N + AES_GCM_CIPHERTEXT_SIZE); // lfsMI :=  H(opkMI  GM||c1MI)
        M_GetPrf(pf_lf_sMI, MMT_sTI, &(MMT_sTI->leaves[leaf_idx]));

        Sig_sMI_GM->wots_sign_leaf = leaf_idx;
        memcpy(Sig_sMI_GM->OPK_MI_GM, OPK_GM, SPX_N);
        memcpy(Sig_sMI_GM->merkle_proof, pf_lf_sMI, SPX_TREE_HEIGHT * SPX_N);

        /*compute the IOC c2MI*/
        unsigned char cipher2[CIPHERTEXT_SIZE + 16] = {0}; // cipher2=ciphertext2 || TAG
        unsigned char ciphertext2[CIPHERTEXT_SIZE] = {0};
        unsigned char ch1[17] = {'K', '-', 'M', 'e', 'm'};
        unsigned char ch2[17] = {'R', '-', 'M', 'e', 'm'};
        unsigned char ke2MI[32] = {0};
        unsigned char re2MI[16] = {0};
        uint8_t TAG[16] = {0};
        uint8_t *AAD = NULL;
        ull_to_bytes(ch1 + 5, 8, tree_idx);
        ull_to_bytes(ch1 + 13, 4, leaf_idx);
        F1(ke2MI, 32, &ctx, ch1, 17); // ke2MI := F1(kGM, “K-Mem”||MI)  MI=(tree_idx || leaf_idx)
        ull_to_bytes(ch2 + 5, 8, tree_idx);
        ull_to_bytes(ch2 + 13, 4, leaf_idx);
        F1(re2MI, 16, &ctx, ch2, 17); // re2MI := F1(kGM, “R-Mem”||MI).
        AES_GCM_SIV *E = new AES_GCM_SIV(ke2MI, re2MI);
        E->Enc(ciphertext2, TAG, AAD, ID, 0, CIPHERTEXT_SIZE); // c2MI := E.Enc(ke2MI, ID; re2MI)
        memcpy(cipher2, ciphertext2, CIPHERTEXT_SIZE);
        memcpy(cipher2 + CIPHERTEXT_SIZE, TAG, 16);
        memcpy(MMT_sTI->leaves[leaf_idx].ciphertext2, cipher2, AES_GCM_CIPHERTEXT_SIZE);

        unsigned char OPK_and_IOC[SPX_N + AES_GCM_CIPHERTEXT_SIZE] = {0}; // OPK_and_IOC=(OPK_ID || c2MI)
        memcpy(OPK_and_IOC, MMT_sTI->leaves[leaf_idx].OPK, SPX_N);
        memcpy(OPK_and_IOC + SPX_N, cipher2, AES_GCM_CIPHERTEXT_SIZE);

        unsigned char sig[SPX_WOTS_BYTES];
        uint32_t counter;
        uint32_t wots_addr2[8] = {0};
        copy_subtree_addr(wots_addr2, wots_addr1);
        struct leaf_info_x1 leaf2;
        INITIALIZE_LEAF_INFO_X1(leaf2, wots_addr2, steps);
        OTS_Sign(sig, OPK_and_IOC, SPX_N + AES_GCM_CIPHERTEXT_SIZE, &ctx, leaf_idx, &leaf2, &counter, rs_GM);
        memcpy(Sig_sMI_GM->wots_sig, sig, SPX_WOTS_BYTES);
        unsigned char counter_bytes[COUNTER_SIZE];
        ull_to_bytes(counter_bytes, COUNTER_SIZE, counter);
        memcpy(Sig_sMI_GM->wots_sig + SPX_WOTS_BYTES, counter_bytes, COUNTER_SIZE);
        Sig_sMI_GM->counter = counter;
        Fp[0]->Punc((unsigned long long)pow(2, SPX_TREE_HEIGHT) * tree_idx + leaf_idx, (int)(SPX_FULL_HEIGHT + SPX_TREE_HEIGHT));
        if (NULL == Fp[0]->Eval((unsigned long long)pow(2, SPX_TREE_HEIGHT) * tree_idx + leaf_idx, (int)(SPX_FULL_HEIGHT + SPX_TREE_HEIGHT)))
        {
            // printf("puncture MI:%llu\n", (unsigned long long)pow(2, SPX_TREE_HEIGHT) * tree_idx + leaf_idx);
        }

        delete[] rs_GM;
    }
    delete[] newseed;
    free(RFCa_MMT);
    return MMT_sTI;
}

void Sign(unsigned char *SIG, unsigned char *sk_ID, struct state_ID *st_ID, long T, const unsigned char *m, uint32_t mlen)
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
        // for(int k=0;k<SPX_N;k++){
        //     printf("%02x",OPK_ID[k]);
        // }
        // printf("\n");
        // for(int k=0;k<SPX_N;k++){
        //     printf("%02x",st_ID->OPK_ID[0][k]);
        // }
        // printf("\n");
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

    /*updated state st_ID ,*/
    for (int i = 0; i < lr - 1; i++)
    {
        if (st_ID->Auth[1] != NULL)
        {
            st_ID->Auth[i] = st_ID->Auth[i + 1];
            memcpy(st_ID->OPK_ID[i], st_ID->OPK_ID[i + 1], SPX_N);
        }
        if (i == lr - 2)
        {
            memset(st_ID->OPK_ID[lr - 1], 0, SPX_N);
            st_ID->Auth[lr - 1] = NULL;
        }
    }
}

int Verify(struct GM *GM1, const unsigned char *m, uint32_t mlen, uint64_t sTI, uint32_t wots_sign_leaf, const unsigned char *SIG, long T)
{
    (void)T;
    int ret1 = 1, ret2 = 0, ret3 = 0, ret4 = 0, ret5 = 0;

    /*c1MI ∈ RL*/
    for (int j = 0; j < MAX_MEMBER; j++)
    {
        if (memcmp(GM1->st_GM.RL[j], SIG + 2 * SPX_N, AES_GCM_CIPHERTEXT_SIZE) == 0)
        {
            ret1 = 0;
            break;
        }
    }

    /*Auth Verify*/
    unsigned char pk[SPX_PK_BYTES];
    memcpy(pk, GM1->sk_GM + (SPX_D + 1) * KEY_SIZE + 2 * SPX_N, SPX_N);
    memcpy(pk + SPX_N, GM1->gpk, SPX_N);
    ret2 = AuthVrfy(pk, SIG + (SPX_TREE_HEIGHT + 2) * SPX_N + 2 * AES_GCM_CIPHERTEXT_SIZE + SPX_WOTS_BYTES + COUNTER_SIZE, SPX_N, SIG + (SPX_TREE_HEIGHT + 2 + 1) * SPX_N + 2 * AES_GCM_CIPHERTEXT_SIZE + SPX_WOTS_BYTES + COUNTER_SIZE, AUTH_BYTES, sTI);
    // printf("Auth Verify=%d\n", ret2);

    /*M.Verify*/
    spx_ctx ctx;
    memcpy(ctx.sk_seed, GM1->sk_GM + (SPX_D + 1) * KEY_SIZE, SPX_N);
    memcpy(ctx.pub_seed, GM1->sk_GM + (SPX_D + 1) * KEY_SIZE + 2 * SPX_N, SPX_N);
    uint32_t tree_addr[8] = {0};
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_layer_addr(tree_addr, (uint32_t)0);
    set_tree_addr(tree_addr, sTI);
    CacheElement *lf = (CacheElement *)malloc(sizeof(CacheElement));
    lf->leaf_index = wots_sign_leaf;
    unsigned char temp[SPX_N + AES_GCM_CIPHERTEXT_SIZE] = {0};
    memcpy(temp, SIG, SPX_N);
    memcpy(temp + SPX_N, SIG + 2 * SPX_N, AES_GCM_CIPHERTEXT_SIZE);
    shake256(lf->leaf_value, SPX_N, temp, SPX_N + AES_GCM_CIPHERTEXT_SIZE);
    ret3 = M_Verify(SIG + (SPX_TREE_HEIGHT + 2) * SPX_N + 2 * AES_GCM_CIPHERTEXT_SIZE + SPX_WOTS_BYTES + COUNTER_SIZE, lf, SIG + 2 * SPX_N + 2 * AES_GCM_CIPHERTEXT_SIZE, &ctx, tree_addr);
    free(lf);
    // printf("M.Verify=%d\n", ret3);

    /*S.verify*/
    unsigned steps[SPX_WOTS_LEN] = {0};
    uint32_t wots_addr[8] = {0};
    set_layer_addr(wots_addr, (uint32_t)0);
    set_tree_addr(wots_addr, sTI);
    set_keypair_addr(wots_addr, wots_sign_leaf);
    struct leaf_info_x1 leaf;
    INITIALIZE_LEAF_INFO_X1(leaf, wots_addr, steps);
    unsigned char OPK_and_IOC[SPX_N + AES_GCM_CIPHERTEXT_SIZE] = {0}; // M=(OPK_ID || c2MI)
    memcpy(OPK_and_IOC, SIG, SPX_N);
    memcpy(OPK_and_IOC + SPX_N, SIG + 2 * SPX_N + AES_GCM_CIPHERTEXT_SIZE, AES_GCM_CIPHERTEXT_SIZE);
    uint32_t counter = (uint32_t)bytes_to_ull(SIG + (SPX_TREE_HEIGHT + 2) * SPX_N + 2 * AES_GCM_CIPHERTEXT_SIZE + SPX_WOTS_BYTES, COUNTER_SIZE);
    ret4 = OTS_Verify(SIG + SPX_N, OPK_and_IOC, SPX_N + AES_GCM_CIPHERTEXT_SIZE, SIG + (SPX_TREE_HEIGHT + 2) * SPX_N + 2 * AES_GCM_CIPHERTEXT_SIZE, &ctx, wots_sign_leaf, &leaf, counter);
    // printf("1-th S.Verify=%d\n",ret4);

    /*S.verify*/
    spx_ctx ctx1;
    memset(&ctx1, 0, sizeof(spx_ctx));
    struct leaf_info_x1 leaf1;
    unsigned char addr[SPX_ADDR_BYTES] = {0};
    INITIALIZE_LEAF_INFO_X1(leaf1, addr, steps);
    set_type(&(leaf1.pk_addr[0]), SPX_ADDR_TYPE_WOTSPK);
    uint32_t counter1 = (uint32_t)bytes_to_ull(SIG + 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2 + 1) * SPX_N + SPX_WOTS_BYTES + COUNTER_SIZE + AUTH_BYTES + SPX_WOTS_BYTES, COUNTER_SIZE);
    ret5 = OTS_Verify(SIG, m, mlen, SIG + 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2 + 1) * SPX_N + SPX_WOTS_BYTES + COUNTER_SIZE + AUTH_BYTES, &ctx1, 0, &leaf1, counter1);
    // printf("2-th S.Verify=%d\n",ret5);

    if (ret1 == 1 && ret2 == 1 && ret3 == 1 && ret4 == 1 && ret5 == 1)
    {
        return 1;
    }
    return 0;
}

unsigned char *Open(struct GM *GM1, const unsigned char *m, uint32_t mlen, uint64_t sTI, uint32_t wots_sign_leaf, unsigned char *SIG, long T)
{
    if (Verify(GM1, m, mlen, sTI, wots_sign_leaf, SIG, T) == 0)
    {
        return NULL;
    }
    spx_ctx ctx;
    memcpy(ctx.sk_seed, GM1->sk_GM + (SPX_D + 1) * KEY_SIZE, SPX_N);
    memcpy(ctx.pub_seed, GM1->sk_GM + (SPX_D + 1) * KEY_SIZE + 2 * SPX_N, SPX_N);
    unsigned char *ID = new unsigned char[ID_SIZE];
    unsigned char ch1[17] = {'K', '-', 'M', 'i', 'x'};
    unsigned char ch2[17] = {'R', '-', 'M', 'i', 'x'};
    unsigned char ke1MI[32] = {0};
    unsigned char re1MI[16] = {0};
    ull_to_bytes(ch1 + 5, 8, sTI);
    ull_to_bytes(ch1 + 13, 4, wots_sign_leaf);
    F1(ke1MI, 32, &ctx, ch1, 17); // ke1MI := F1(kGM, “K-Mix”||MI)  MI=(tree_idx || leaf_idx)
    ull_to_bytes(ch2 + 5, 8, sTI);
    ull_to_bytes(ch2 + 13, 4, wots_sign_leaf);
    F1(re1MI, 16, &ctx, ch2, 17); // re1MI := F1(kGM, “R-Mix”||MI).
    AES_GCM_SIV *E = new AES_GCM_SIV(ke1MI, re1MI);
    unsigned char ciphertext[CIPHERTEXT_SIZE] = {0};
    uint8_t TAG[16] = {0};
    uint8_t *AAD = NULL;
    memcpy(ciphertext, SIG + 2 * SPX_N, CIPHERTEXT_SIZE);
    memcpy(TAG, SIG + 2 * SPX_N + CIPHERTEXT_SIZE, 16);
    E->Dec(ID, TAG, AAD, ciphertext, 0, CIPHERTEXT_SIZE);
    return ID;
}

void Revoke(struct GM *GM1, unsigned char *ID, unsigned char *RSS, uint32_t mlen, uint64_t sTI, uint32_t wots_sign_leaf, long T)
{
    int ret1 = 0, ret2 = 0;
    unsigned char empty[AES_GCM_CIPHERTEXT_SIZE] = {0};
    ret1 = Verify(GM1, RSS + 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2 + 1) * SPX_N + 2 * (SPX_WOTS_BYTES + COUNTER_SIZE) + AUTH_BYTES, mlen, sTI, wots_sign_leaf, RSS, T);
    unsigned char *ID1 = Open(GM1, RSS + 2 * AES_GCM_CIPHERTEXT_SIZE + (SPX_TREE_HEIGHT + 2 + 1) * SPX_N + 2 * (SPX_WOTS_BYTES + COUNTER_SIZE) + AUTH_BYTES, mlen, sTI, wots_sign_leaf, RSS, T);
    if (memcmp(ID, ID1, ID_SIZE) == 0)
    {
        ret2 = 1;
    }
    if (ret1 == 1 && ret2 == 1)
    {
        for (int i = 0; i < MAX_MEMBER; i++)
        {
            if (memcmp(GM1->st_GM.RL[i], empty, AES_GCM_CIPHERTEXT_SIZE) == 0)
            {
                memcpy(GM1->st_GM.RL[i], RSS + 2 * SPX_N, AES_GCM_CIPHERTEXT_SIZE);
                break;
            }
        }
    }
}
