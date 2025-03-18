#ifndef SPX_HASH_H
#define SPX_HASH_H

#include <stdint.h>
#include <math.h>
#include "context.h"
#include "utils.h"
#include "PRG/prg.h"

void initialize_hash_function(spx_ctx *ctx);

void prf_addr(unsigned char* out,const spx_ctx* ctx,
              const uint32_t addr[8]);
void OTS_skGen(unsigned char* out,const spx_ctx* ctx,
              const uint32_t addr[8],unsigned char* rs);

/*generate the wots's sk of layer=1 to layer d-1*/
void prf_addr1(unsigned char *out, const spx_ctx *ctx,
              const uint32_t addr[8],PunPRF* PunPRFi,unsigned char cache[KEY_SIZE*LEAF_NUM]);

void F1(unsigned char* out,int outlen,const spx_ctx *ctx,
        const unsigned char* ch,int chlen);
void F2(uint64_t *tree,uint32_t* leaf_idx,const unsigned char *ks,unsigned char* ID,unsigned char *OPK_ID,uint32_t ctr);

void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const spx_ctx *ctx);

void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx);

#endif
