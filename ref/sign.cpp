#include <stddef.h>
#include <string.h>
#include <stdint.h>

#include "api.h"
#include "params.h"
#include "wots.h"
#include "hash.h"
#include "thash.h"
#include "address.h"
#include "randombytes.h"
#include "wotsx1.h"
#include "merkle.h"
#include "counters.h"

/*
 * Returns the length of a secret key, in bytes
 */
unsigned long long crypto_sign_secretkeybytes(void)
{
    return CRYPTO_SECRETKEYBYTES;
}

/*
 * Returns the length of a public key, in bytes
 */
unsigned long long crypto_sign_publickeybytes(void)
{
    return CRYPTO_PUBLICKEYBYTES;
}

/*
 * Returns the length of a signature, in bytes
 */
unsigned long long crypto_sign_bytes(void)
{
    return CRYPTO_BYTES;
}

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
unsigned long long crypto_sign_seedbytes(void)
{
    return CRYPTO_SEEDBYTES;
}

/*
 * Generates an SPX key pair given a seed of length
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed, PunPRF *PunPRFi)
{
    spx_ctx ctx;

    /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
    memcpy(sk, seed, CRYPTO_SEEDBYTES);

    memcpy(pk, sk + 2 * SPX_N, SPX_N);

    memcpy(ctx.pub_seed, pk, SPX_N);
    memcpy(ctx.sk_seed, sk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    /* Compute root node of the top-most subtree. */
    merkle_gen_root(sk + 3 * SPX_N, &ctx, PunPRFi);

    memcpy(pk + SPX_N, sk + 3 * SPX_N, SPX_N);

    return 0;
}

/* Setup
 * Generates an SPX key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 * Generate a PunPRF instance each layer(from layer 0 to layer d) */
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk, PunPRF *PunPRF1[SPX_D + 1])
{
    unsigned char seed[CRYPTO_SEEDBYTES];
    randombytes(seed, CRYPTO_SEEDBYTES);

    for (uint32_t j = 0; j < SPX_D + 1; j++)
    {
        PunPRF1[j] = new PunPRF(seed, j);
    }
    crypto_sign_seed_keypair(pk, sk, seed, PunPRF1[SPX_D]);

    return 0;
}

/**
 * Returns an array containing a detached signature.
 */
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk, PunPRF *PunPRF1[SPX_D + 1], unsigned char cache[SPX_D][KEY_SIZE * LEAF_NUM])
{
    spx_ctx ctx;

    const unsigned char *sk_prf = sk + SPX_N;
    const unsigned char *pk = sk + 2 * SPX_N;

    unsigned char optrand[SPX_N];
    unsigned char mhash[SPX_WOTS_MSG_BYTES];
    unsigned char root[SPX_N];
    unsigned long long i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t counter;
    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    randombytes(optrand, SPX_N);
    /* Compute the digest randomization value. */
    gen_message_random(sig, sk_prf, optrand, m, mlen, &ctx);
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N;
    // printf("2-th tree=%lu \n",tree);
    // printf("2-th leaf_idx=%u \n",idx_leaf);

    memcpy(root, mhash, SPX_N);

    for (i = 0; i < SPX_D; i++)
    {
        // printf("idx_leaf=%u\n",idx_leaf);
        set_layer_addr(tree_addr, (uint32_t)i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        merkle_sign(sig, root, &ctx, wots_addr, tree_addr, idx_leaf, &counter, PunPRF1[i + 1], cache[i]);
        if (counter == 0)
            return -1;
        PunPRF1[i + 1]->Punc((unsigned long long)pow(2, SPX_TREE_HEIGHT) * tree + idx_leaf, (int)(SPX_FULL_HEIGHT - i * SPX_TREE_HEIGHT));
        // std::cout << "Punctured leaf " << (unsigned long long)pow(2,SPX_TREE_HEIGHT)*tree+idx_leaf << " at depth " << SPX_FULL_HEIGHT - i * SPX_TREE_HEIGHT << "." << std::endl;

        save_wots_counter(counter, sig);
        sig += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N + COUNTER_SIZE;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    *siglen = SPX_BYTES;

    return 0;
}

int GetAuth(uint8_t *Auth, size_t *Authlen,
            PunPRF *Fp[SPX_D + 1], uint8_t *sk,
            const uint8_t *m, size_t mlen,
            uint64_t sTI, unsigned char cache[SPX_D][KEY_SIZE * LEAF_NUM])
{
    spx_ctx ctx;
    const unsigned char *pk = sk + 2 * SPX_N;
    unsigned char root[SPX_N];
    unsigned long long i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t counter;
    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    memcpy(root, m, mlen);

    /* Update the indices for the next layer. */
    idx_leaf = (sTI & ((1 << SPX_TREE_HEIGHT) - 1));
    tree = sTI >> SPX_TREE_HEIGHT;

    for (i = 0; i < SPX_D; i++)
    {
        // printf("idx_leaf=%u\n",idx_leaf);
        set_layer_addr(tree_addr, (uint32_t)i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        merkle_sign(Auth, root, &ctx, wots_addr, tree_addr, idx_leaf, &counter, Fp[i + 1], cache[i]);
        if (counter == 0)
            return -1;
        Fp[i + 1]->Punc((unsigned long long)pow(2, SPX_TREE_HEIGHT) * tree + idx_leaf, (int)(SPX_FULL_HEIGHT - i * SPX_TREE_HEIGHT));
        // std::cout << "Punctured leaf " << (unsigned long long)pow(2,SPX_TREE_HEIGHT)*tree+idx_leaf << " at depth " << SPX_FULL_HEIGHT - i * SPX_TREE_HEIGHT << "." << std::endl;

        save_wots_counter(counter, Auth);
        Auth += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N + COUNTER_SIZE;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    *Authlen = AUTH_BYTES;

    return 0;
}

int AuthVrfy(const uint8_t *pk,
             const uint8_t *m, size_t mlen,
             const uint8_t *Auth, size_t Authlen,
             uint64_t sTI)
{
    spx_ctx ctx;
    const unsigned char *pub_root = pk + SPX_N;
    unsigned char wots_pk[SPX_WOTS_BYTES];
    unsigned char root[SPX_N];
    unsigned char leaf[SPX_N];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};
    uint32_t counter;

    if (Authlen != AUTH_BYTES)
    {
        return -2;
    }

    memcpy(ctx.pub_seed, pk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    memcpy(root, m, mlen);

    idx_leaf = (sTI & ((1 << SPX_TREE_HEIGHT) - 1));
    tree = sTI >> SPX_TREE_HEIGHT;

    /* For each subtree.. */
    for (i = 0; i < SPX_D; i++)
    {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        counter = get_wots_counter(Auth);
        //printf("%u-th leval counter=%u\n",i,counter);
        if (counter == 0)
            return -1;
        wots_pk_from_sig(wots_pk, Auth, root, &ctx, wots_addr, counter);
        Auth += SPX_WOTS_BYTES;

        /* Compute the leaf node using the WOTS public key. */
        thash(leaf, wots_pk, SPX_WOTS_LEN, &ctx, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root(root, leaf, idx_leaf, 0, Auth, SPX_TREE_HEIGHT,
                     &ctx, tree_addr);
        
        Auth += SPX_TREE_HEIGHT * SPX_N + COUNTER_SIZE;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, SPX_N))
    {
        printf("root ");
        for (int j = 0; j < SPX_N; j++)
        {
            printf("%02x", root[j]);
        }
        printf("\n");
        return 0;
    }

    return 1;
}

/**
 * Verifies a detached signature and message under a given public key.
 */
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk)
{
    spx_ctx ctx;
    const unsigned char *pub_root = pk + SPX_N;
    unsigned char mhash[SPX_WOTS_MSG_BYTES];
    unsigned char wots_pk[SPX_WOTS_BYTES];
    unsigned char root[SPX_N];
    unsigned char leaf[SPX_N];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};
    uint32_t counter;

    if (siglen != SPX_BYTES)
    {
        return -1;
    }

    memcpy(ctx.pub_seed, pk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N;

    memcpy(root, mhash, SPX_N);

    /* For each subtree.. */
    for (i = 0; i < SPX_D; i++)
    {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        counter = get_wots_counter(sig);

        if (counter == 0)
            return -1;
        wots_pk_from_sig(wots_pk, sig, root, &ctx, wots_addr, counter);
        sig += SPX_WOTS_BYTES;

        /* Compute the leaf node using the WOTS public key. */
        thash(leaf, wots_pk, SPX_WOTS_LEN, &ctx, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT,
                     &ctx, tree_addr);
        // if(i==0){
        //     printf("root ");
        //     for(int j=0;j<SPX_N;j++){
        //         printf("%02x ",root[j]);
        //     }
        //     printf("\n");
        // }
        sig += SPX_TREE_HEIGHT * SPX_N + COUNTER_SIZE;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, SPX_N))
    {
        return -1;
    }

    return 0;
}

/**
 * Returns an array containing the signature followed by the message.
 */
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk, PunPRF *PunPRF1[SPX_D + 1])
{
    size_t siglen;
    unsigned char cache[SPX_D][KEY_SIZE * LEAF_NUM];

    crypto_sign_signature(sm, &siglen, m, (size_t)mlen, sk, PunPRF1, cache);

    memmove(sm + SPX_BYTES, m, mlen);
    *smlen = siglen + mlen;

    return 1;
}

/**
 * Verifies a given signature-message pair under a given public key.
 */
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk)
{
    /* The API caller does not necessarily know what size a signature should be
       but SPHINCS+ signatures are always exactly SPX_BYTES. */
    if (smlen < SPX_BYTES)
    {
        memset(m, 0, smlen);
        *mlen = 0;
        return 0;
    }

    *mlen = smlen - SPX_BYTES;

    if (crypto_sign_verify(sm, SPX_BYTES, sm + SPX_BYTES, (size_t)*mlen, pk))
    {
        memset(m, 0, smlen);
        *mlen = 0;
        return 0;
    }

    /* If verification was successful, move the message to the right place. */
    memmove(m, sm + SPX_BYTES, *mlen);

    return 1;
}
