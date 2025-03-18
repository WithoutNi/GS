#if !defined( WOTSX1_H_ )
#define WOTSX1_H_ 

#include <string.h>
#include "utils.h"

/*
 * This is here to provide an interface to the internal wots_gen_leafx1
 * routine.  While this routine is not referenced in the package outside of
 * wots.c, it is called from the stand-alone benchmark code to characterize
 * the performance
 */
struct leaf_info_x1 {
    unsigned char *wots_sig;
    unsigned char* IOC;
    uint32_t wots_sign_leaf; /* The index of the WOTS we're using to sign */
    uint32_t *wots_steps;
    uint32_t leaf_addr[8];
    uint32_t pk_addr[8];
};

/* Macro to set the leaf_info to something 'benign', that is, it would */
/* run with the same time as it does during the real signing process */
/* Used only by the benchmark code */
#define INITIALIZE_LEAF_INFO_X1(info, addr, step_buffer) { \
    info.wots_sig = 0;             \
    info.IOC=0;                    \
    info.wots_sign_leaf = ~0;      \
    info.wots_steps = step_buffer; \
    memcpy( &info.leaf_addr[0], addr, 32 ); \
    memcpy( &info.pk_addr[0], addr, 32 ); \
}

// void compute_wots_pk(unsigned char *dest,
//                    const spx_ctx *ctx,
//                    uint32_t leaf_idx, void *v_info);
void OTS_KGen(unsigned char *dest,
                     const spx_ctx *ctx,
                     uint32_t leaf_idx, void *v_info,unsigned char* rs);
                     
void OTS_Sign(unsigned char* sig,const unsigned char* m,uint32_t mlen, 
              const spx_ctx *ctx,uint32_t leaf_idx,void *v_info,uint32_t *counter_out,unsigned char* rs_GM);

void OTS_PK_From_Sig(unsigned char *pk, const unsigned char *sig,
                    const unsigned char *m, uint32_t mlen, const spx_ctx *ctx, uint32_t leaf_idx,
                    void *v_info, uint32_t counter);

int OTS_Verify(const unsigned char* OPK,const unsigned char* m,uint32_t mlen,const unsigned char *sig,const spx_ctx *ctx,uint32_t leaf_idx,void* v_info,uint32_t counter);

void wots_gen_leafx1(unsigned char *dest,
                   const spx_ctx *ctx,
                   uint32_t leaf_idx, void *v_info,PunPRF* PunPRFi,unsigned char cache[KEY_SIZE*LEAF_NUM]);
                     

void wots_pk_from_sigx1(unsigned char *pk,const unsigned char *sig, 
                      const unsigned char *msg,const spx_ctx *ctx,uint32_t leaf_idx,
                      void *v_info,uint32_t counter);                  
#endif /* WOTSX1_H_ */
