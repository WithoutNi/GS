#include <stdint.h>
#include <string.h>

#include "address.h"
#include "params.h"
#include "hash.h"
#include "fips202.h"

/* For SHAKE256, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
void initialize_hash_function(spx_ctx *ctx)
{
    (void)ctx; /* Suppress an 'unused parameter' warning. */
}

/*
 * Computes PRF(pk_seed, sk_seed, addr)
 */
void prf_addr(unsigned char *out, const spx_ctx *ctx,
              const uint32_t addr[8])
{
    unsigned char buf[2 * SPX_N + SPX_ADDR_BYTES];

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N + SPX_ADDR_BYTES, ctx->sk_seed, SPX_N);

    shake256(out, SPX_N, buf, 2 * SPX_N + SPX_ADDR_BYTES);
}

void OTS_skGen(unsigned char *out, const spx_ctx *ctx,
               const uint32_t addr[8], unsigned char *rs)
{
    unsigned char buf[SPX_N + SPX_ADDR_BYTES + KEY_SIZE];

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N + SPX_ADDR_BYTES, rs, KEY_SIZE);

    shake256(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + KEY_SIZE);
}

/*generate the wots's sk of layer=0 to layer d-1*/
void prf_addr1(unsigned char *out, const spx_ctx *ctx,
               const uint32_t addr[8], PunPRF *PunPRFi, unsigned char cache[KEY_SIZE * LEAF_NUM])
{
    unsigned char buf[SPX_N + SPX_ADDR_BYTES + KEY_SIZE];

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_ADDR_BYTES);

    /*generate a newseed*/
    unsigned char *newseed = new unsigned char[KEY_SIZE];
    uint32_t layer = get_layer_addr(addr);
    uint32_t leaf_idx = get_keypair_addr(addr);
    unsigned long long tree = bytes_to_ull((unsigned char *)addr + SPX_OFFSET_TREE, 8);
    newseed = PunPRFi->Eval((unsigned long long)pow(2, SPX_TREE_HEIGHT) * tree + leaf_idx, (int)(SPX_FULL_HEIGHT - layer * SPX_TREE_HEIGHT));
    if (newseed != NULL)
    {
        memcpy(cache+leaf_idx*KEY_SIZE,newseed,KEY_SIZE);       //cache memory the newseed of the leaves   
        memcpy(buf + SPX_N + SPX_ADDR_BYTES, newseed, KEY_SIZE);
    }
    else
    {
        memcpy(buf + SPX_N + SPX_ADDR_BYTES, cache+leaf_idx*KEY_SIZE, KEY_SIZE);        //when the leaf is punctured,obtained the newseed from the cache
    }
    shake256(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + KEY_SIZE);
    delete[] newseed;
}

void F1(unsigned char *out, int outlen, const spx_ctx *ctx,
        const unsigned char *ch, int chlen)
{
    unsigned char *buf = (unsigned char *)malloc(SPX_N + chlen);

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, ch, chlen);

    shake256(out, outlen, buf, SPX_N + chlen);
    free(buf);
}

/**
 * Computes the message-dependent randomness R, using a secret seed and an
 * optional randomization value as well as the message.
 */
void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const spx_ctx *ctx)
{
    (void)ctx;
    uint64_t s_inc[26];

    shake256_inc_init(s_inc);
    shake256_inc_absorb(s_inc, sk_prf, SPX_N);
    shake256_inc_absorb(s_inc, optrand, SPX_N);
    shake256_inc_absorb(s_inc, m, mlen);
    shake256_inc_finalize(s_inc);
    shake256_inc_squeeze(R, SPX_N, s_inc);
}

void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx)
{
    (void)ctx;
#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_WOTS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    unsigned char buf[SPX_DGST_BYTES];
    unsigned char *bufp = buf;
    uint64_t s_inc[26];

    shake256_inc_init(s_inc);
    shake256_inc_absorb(s_inc, R, SPX_N);
    shake256_inc_absorb(s_inc, pk, SPX_PK_BYTES);
    shake256_inc_absorb(s_inc, m, mlen);
    shake256_inc_finalize(s_inc);
    shake256_inc_squeeze(buf, SPX_DGST_BYTES, s_inc);

    memcpy(digest, bufp, SPX_WOTS_MSG_BYTES);
    bufp += SPX_WOTS_MSG_BYTES;

#if SPX_TREE_BITS > 64
#error For given height and depth, 64 bits cannot represent all subtrees
#endif

    if (SPX_D == 1)
    {
        *tree = 0;
    }
    else
    {
        *tree = bytes_to_ull(bufp, SPX_TREE_BYTES);
        *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    }
    bufp += SPX_TREE_BYTES;

    *leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}

void F2(uint64_t *tree, uint32_t *leaf_idx, const unsigned char *ks, unsigned char *ID, unsigned char *OPK_ID, uint32_t ctr)
{
#define SPX_TREE1_BITS (SPX_TREE_HEIGHT * (SPX_D))
#define SPX_TREE1_BYTES ((SPX_TREE1_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST1_BYTES (SPX_TREE1_BYTES + SPX_LEAF_BYTES)
    unsigned char buf[SPX_DGST1_BYTES];
    unsigned char *bufp = buf;
    uint64_t s_inc[26];

    shake256_inc_init(s_inc);
    shake256_inc_absorb(s_inc, ks, KEY_SIZE);
    shake256_inc_absorb(s_inc, ID, CIPHERTEXT_SIZE);
    shake256_inc_absorb(s_inc, OPK_ID, SPX_N);
    shake256_inc_absorb(s_inc, (unsigned char *)&ctr, 4);
    shake256_inc_finalize(s_inc);
    shake256_inc_squeeze(buf, SPX_DGST1_BYTES, s_inc);

#if SPX_TREE1_BITS > 64
#error For given height and depth, 64 bits cannot represent all subtrees
#endif

    if (SPX_D == 1)
    {
        *tree = 0;
    }
    else
    {
        *tree = bytes_to_ull(bufp, SPX_TREE1_BYTES);
        *tree &= (~(uint64_t)0) >> (64 - SPX_TREE1_BITS);
    }
    bufp += SPX_TREE1_BYTES;

    *leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}
