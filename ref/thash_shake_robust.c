#include <stdint.h>
#include <string.h>

#include "thash.h"
#include "address.h"
#include "params.h"

#include "fips202.h"

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    unsigned char* buf=(unsigned char*)malloc(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N);
    unsigned char* bitmask=(unsigned char*)malloc(inblocks * SPX_N);
    unsigned int i;

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_ADDR_BYTES);

    shake256(bitmask, inblocks * SPX_N, buf, SPX_N + SPX_ADDR_BYTES);

    for (i = 0; i < inblocks * SPX_N; i++) {
        buf[SPX_N + SPX_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    shake256(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N);
    free(buf);
    free(bitmask);
}

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash_init_bitmask(unsigned char *bitmask_out, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    unsigned char* buf=(unsigned char*)malloc(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N);
    unsigned char* bitmask=(unsigned char*)malloc(inblocks * SPX_N);

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_ADDR_BYTES);

    shake256(bitmask, inblocks * SPX_N, buf, SPX_N + SPX_ADDR_BYTES);
    memcpy(bitmask_out, bitmask, inblocks * SPX_N);
    free(buf);
    free(bitmask);
}

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash_fin(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8], const unsigned char *bitmask)
{
    unsigned char* buf=(unsigned char*)malloc(SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N);
    unsigned int i;

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_ADDR_BYTES);

    for (i = 0; i < inblocks * SPX_N; i++) {
        buf[SPX_N + SPX_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    shake256(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N);
    free(buf);
}
