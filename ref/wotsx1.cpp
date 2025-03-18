#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "hash.h"
#include "thash.h"
#include "wots.h"
#include "wotsx1.h"
#include "address.h"
#include "params.h"

/*This generates a WOTS public key*/
void OTS_KGen(unsigned char *dest,
                     const spx_ctx *ctx,
                     uint32_t leaf_idx, void *v_info, unsigned char* rs)
{
    struct leaf_info_x1 *info = (struct leaf_info_x1 *)v_info;
    uint32_t *leaf_addr = info->leaf_addr;
    uint32_t *pk_addr = info->pk_addr;
    unsigned int i, k;
    unsigned char pk_buffer[SPX_WOTS_BYTES];
    unsigned char *buffer;
    uint32_t wots_k_mask;

    if (leaf_idx == info->wots_sign_leaf)
    {
        /* We're traversing the leaf that's signing; generate the WOTS */
        /* signature */
        wots_k_mask = 0;
    }
    else
    {
        /* Nope, we're just generating pk's; turn off the signature logic */
        wots_k_mask = ~0;
    }

    set_keypair_addr(leaf_addr, leaf_idx);
    set_keypair_addr(pk_addr, leaf_idx);

    for (i = 0, buffer = pk_buffer; i < SPX_WOTS_LEN; i++, buffer += SPX_N)
    {
        uint32_t wots_k = info->wots_steps[i] | wots_k_mask; /* Set wots_k to */
        /* the step if we're generating a signature, ~0 if we're not */

        /* Start with the secret seed */
        set_chain_addr(leaf_addr, i);
        set_hash_addr(leaf_addr, 0);
        set_type(leaf_addr, SPX_ADDR_TYPE_WOTSPRF);

        OTS_skGen(buffer, ctx, leaf_addr,rs);

        set_type(leaf_addr, SPX_ADDR_TYPE_WOTS);

        /* Iterate down the WOTS chain */
        for (k = 0;; k++)
        {
            /* Check if this is the value that needs to bes saved as a */
            /* part of the WOTS signature */
            if (k == wots_k)
            {
                memcpy(info->wots_sig + i * SPX_N, buffer, SPX_N);
            }

            /* Check if we hit the top of the chain */
            if (k == SPX_WOTS_W - 1)
                break;

            /* Iterate one step on the chain */
            set_hash_addr(leaf_addr, k);

            thash(buffer, buffer, 1, ctx, leaf_addr);
        }
    }

    /* Do the final thash to generate the public keys */
    thash(dest, pk_buffer, SPX_WOTS_LEN, ctx, pk_addr);
}

/*generate the leaves of hypertree*/
void wots_gen_leafx1(unsigned char *dest,
                     const spx_ctx *ctx,
                     uint32_t leaf_idx, void *v_info, PunPRF *PunPRFi,unsigned char cache[KEY_SIZE*LEAF_NUM])
{
    struct leaf_info_x1 *info = (struct leaf_info_x1 *)v_info;
    uint32_t *leaf_addr = info->leaf_addr;
    uint32_t *pk_addr = info->pk_addr;
    unsigned int i, k;
    unsigned char pk_buffer[SPX_WOTS_BYTES];
    unsigned char *buffer;
    uint32_t wots_k_mask;

    if (leaf_idx == info->wots_sign_leaf)
    {
        /* We're traversing the leaf that's signing; generate the WOTS */
        /* signature */
        wots_k_mask = 0;
    }
    else
    {
        /* Nope, we're just generating pk's; turn off the signature logic */
        wots_k_mask = ~0;
    }

    set_keypair_addr(leaf_addr, leaf_idx);
    set_keypair_addr(pk_addr, leaf_idx);

    for (i = 0, buffer = pk_buffer; i < SPX_WOTS_LEN; i++, buffer += SPX_N)
    {
        uint32_t wots_k = info->wots_steps[i] | wots_k_mask; /* Set wots_k to */
        /* the step if we're generating a signature, ~0 if we're not */

        /* Start with the secret seed */
        set_chain_addr(leaf_addr, i);
        set_hash_addr(leaf_addr, 0);
        set_type(leaf_addr, SPX_ADDR_TYPE_WOTSPRF);
        // uint32_t lf=get_keypair_addr(leaf_addr);
        // printf("leaf_idx=%u\n",lf);

        prf_addr1(buffer, ctx, leaf_addr, PunPRFi,cache);

        set_type(leaf_addr, SPX_ADDR_TYPE_WOTS);

        /* Iterate down the WOTS chain */
        for (k = 0;; k++)
        {
            /* Check if this is the value that needs to bes saved as a */
            /* part of the WOTS signature */
            if (k == wots_k)
            {
                memcpy(info->wots_sig + i * SPX_N, buffer, SPX_N);
            }

            /* Check if we hit the top of the chain */
            if (k == SPX_WOTS_W - 1)
                break;

            /* Iterate one step on the chain */
            set_hash_addr(leaf_addr, k);

            thash(buffer, buffer, 1, ctx, leaf_addr);
        }
    }

    /* Do the final thash to generate the public keys */
    thash(dest, pk_buffer, SPX_WOTS_LEN, ctx, pk_addr);

}

/*compute a wots+c signature*/
void OTS_Sign(unsigned char* sig,const unsigned char* m,uint32_t mlen, 
              const spx_ctx *ctx,uint32_t leaf_idx,void *v_info,uint32_t *counter_out,unsigned char* rs_GM)
{
#define MAX_HASH_TRIALS_WOTS (1 << (20))
    unsigned char bitmask[SPX_N];
    unsigned int steps[SPX_WOTS_LEN]={0}; 
    struct leaf_info_x1 *info = (struct leaf_info_x1 *)v_info;
    uint32_t *leaf_addr = info->leaf_addr;
    uint32_t *tmp_pk_addr = info->pk_addr;
    uint32_t pk_addr[8] = {0};
    for (int j = 0; j < 8; j++)
    {
        pk_addr[j] = tmp_pk_addr[j];
    }
    unsigned int i, k;
    unsigned char sig_buffer[SPX_WOTS_BYTES];
    unsigned char *buffer;

    unsigned char msg[SPX_N]={0};
    shake256(msg,SPX_N,m,mlen);

    /*Initial paramaters for custom thash & counter search*/
    unsigned char digest[SPX_N];
    uint32_t counter = 0;
    int csum;
    uint32_t to_sign = ~0;
    uint32_t mask = (~0U << (8 - WOTS_ZERO_BITS));
    set_keypair_addr(pk_addr, leaf_idx);
    set_keypair_addr(leaf_addr, leaf_idx);

    /* Code for counter search */
    *counter_out = 0;
    if (leaf_idx != to_sign)
    {
        /*Set thash address for custom hash*/
        set_type(pk_addr, SPX_ADDR_TYPE_COMPRESS_WOTS);
        thash_init_bitmask(bitmask, 1, ctx, pk_addr);

        /*Search for correct counter */
        while (1)
        {
            counter++;
            if (counter > MAX_HASH_TRIALS_WOTS)
                return;
            ull_to_bytes(((unsigned char *)(pk_addr)) + (SPX_OFFSER_COUNTER), COUNTER_SIZE, counter);
            thash_fin(digest, msg, 1, ctx, pk_addr, bitmask);
            if (((digest[SPX_N - 1]) & (mask)) == 0)
            {
                csum = chain_lengths(steps, digest);
                if (csum == WANTED_CHECKSUM)
                {
                    *counter_out = counter;
                    break;
                }
            }
        }

        /*Restore initial parameters for tree hash*/
        set_type(pk_addr, SPX_ADDR_TYPE_WOTSPK);
        ull_to_bytes(((unsigned char *)(pk_addr)) + (SPX_OFFSER_COUNTER), COUNTER_SIZE, 0);
    }

    for (i = 0, buffer = sig_buffer; i < SPX_WOTS_LEN; i++, buffer += SPX_N)
    {
        /* Start with the secret seed */
        set_chain_addr(leaf_addr, i);
        set_hash_addr(leaf_addr, 0);
        set_type(leaf_addr, SPX_ADDR_TYPE_WOTSPRF);

        OTS_skGen(buffer, ctx, leaf_addr, rs_GM);

        set_type(leaf_addr, SPX_ADDR_TYPE_WOTS);

        /* Iterate down the WOTS chain */
        for (k = 0; k < steps[i]; k++)
        {
            set_hash_addr(leaf_addr, k);
            thash(buffer, buffer, 1, ctx, leaf_addr);
        }
        memcpy(sig + i * SPX_N, buffer, SPX_N);
    }
 
}

/*verify the WOTS+C signature ,valid return 1,otherwise return 0*/
int OTS_Verify(const unsigned char* OPK,const unsigned char* m,uint32_t mlen,const unsigned char *sig,const spx_ctx *ctx,uint32_t leaf_idx,void* v_info,uint32_t counter)
{
    int ret=1;
    unsigned char OPK1[SPX_WOTS_BYTES]={0};
    unsigned char msg[SPX_N]={0};
    shake256(msg,SPX_N,m,mlen);
    wots_pk_from_sigx1(OPK1,sig,msg,ctx,leaf_idx,v_info,counter);
    if(memcmp(OPK,OPK1,SPX_N)){
        ret=0;
    }
    return ret;
}

void OTS_PK_From_Sig(unsigned char *pk, const unsigned char *sig,
                    const unsigned char *m, uint32_t mlen, const spx_ctx *ctx, uint32_t leaf_idx,
                    void *v_info, uint32_t counter)
{
    unsigned char msg[SPX_N];
    shake256(msg,SPX_N,m,mlen);
    wots_pk_from_sigx1(pk,sig,msg,ctx,leaf_idx,v_info,counter);
}

/*compute a wots+c's pk from the wots+c's sig*/
void wots_pk_from_sigx1(unsigned char *pk, const unsigned char *sig,
                        const unsigned char *msg, const spx_ctx *ctx, uint32_t leaf_idx,
                        void *v_info, uint32_t counter)
{
    struct leaf_info_x1 *info = (struct leaf_info_x1 *)v_info;
    uint32_t *leaf_addr = info->leaf_addr;
    uint32_t *pk_addr = info->pk_addr;

    unsigned int i, k;
    unsigned char sig_buffer[SPX_WOTS_BYTES];
    memcpy(sig_buffer, sig, SPX_WOTS_BYTES);
    unsigned char *buffer;

    set_keypair_addr(leaf_addr, leaf_idx);
    set_keypair_addr(pk_addr, leaf_idx);

    unsigned int lengths[SPX_WOTS_LEN];
    uint32_t mask = (~0U << (8 - WOTS_ZERO_BITS));
    unsigned char bitmask[SPX_N];

    /*Initial parameters for validation of checksum*/
    int csum;
    unsigned char digest[SPX_N];

    /*Set thash address for custom hash to type 6 & PK format*/
    uint32_t wots_pk_addr[8] = {0};
    for (int j = 0; j < 8; j++)
    {
        wots_pk_addr[j] = pk_addr[j];
    }
    set_type(wots_pk_addr, SPX_ADDR_TYPE_COMPRESS_WOTS);
    thash_init_bitmask(bitmask, 1, ctx, wots_pk_addr);

    /*Set padding*/
    ull_to_bytes(((unsigned char *)(wots_pk_addr)) + (SPX_OFFSER_COUNTER), COUNTER_SIZE, counter);
    /*Calculate checksum*/
    thash_fin(digest, msg, 1, ctx, wots_pk_addr, bitmask);

    csum = chain_lengths(lengths, digest);

    /*Validate Checksum*/
    if ((csum != WANTED_CHECKSUM) || (((digest[SPX_N - 1]) & (mask)) != 0))
    {
        memset(pk, 0, SPX_PK_BYTES);
    }

    for (i = 0, buffer = sig_buffer; i < SPX_WOTS_LEN; i++, buffer += SPX_N)
    {
        set_chain_addr(leaf_addr, i);
        set_type(leaf_addr, SPX_ADDR_TYPE_WOTS);
        /* Iterate down the WOTS chain */
        for (k = lengths[i]; k < SPX_WOTS_W - 1; k++)
        {
            /* Iterate one step on the chain */
            set_hash_addr(leaf_addr, k);
            thash(buffer, buffer, 1, ctx, leaf_addr);
        }
        memcpy(pk + i * SPX_N, buffer, SPX_N);
    }

    /* Do the final thash to generate the public keys */
    set_type(pk_addr, SPX_ADDR_TYPE_WOTSPK);
    thash(pk, pk, SPX_WOTS_LEN, ctx, pk_addr);
}
