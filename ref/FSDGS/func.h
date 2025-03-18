#include "../api.h"
#include "../context.h"
#include "../wotsx1.h"
#include "../address.h"
#include "../hash.h"
#include "../thash.h"
#include "../randombytes.h"
#include "MoMST.h"

#define CRYPTO_ALGNAME "Group Signature"
#define ID_SIZE CIPHERTEXT_SIZE
#define MAX_MEMBER 2
#define lr 1

struct state_GM
{
    unsigned char RegIDL[MAX_MEMBER][ID_SIZE];
    unsigned char RL[MAX_MEMBER][AES_GCM_CIPHERTEXT_SIZE];
    unsigned char *Auth;
    unsigned long Authlen;
};
struct GM
{
    unsigned char sk_GM[(SPX_D + 1) * KEY_SIZE + CRYPTO_SEEDBYTES];
    unsigned char gpk[SPX_N];
    struct state_GM st_GM;
};

struct state_ID
{
    unsigned char OPK_ID[lr][SPX_N];
    unsigned char *Auth[lr];
};
struct Mem
{
    unsigned char ID[ID_SIZE];
    unsigned char sk_ID[KEY_SIZE];
    struct state_ID st_ID;
    unsigned char *RR_ID[lr];
};

struct MountIdx
{
    uint64_t sTI;
    uint32_t sMI;
};

struct RFCa
{
    unsigned char ID[ID_SIZE];
    unsigned char OPK_ID[SPX_N];
    struct MountIdx MI;
};

struct MMT_Sig
{
    unsigned char wots_sig[SPX_WOTS_BYTES + COUNTER_SIZE];
    unsigned char merkle_proof[SPX_TREE_HEIGHT * SPX_N];
    unsigned char OPK_MI_GM[SPX_N];
    uint32_t wots_sign_leaf;
    uint32_t counter;
};

/*The GM initialization algorithm return a group manager,which includes a
 group public and private key pair (gpk,skGM), 
 the group management state st_GM of the group manager GM, and a revocation list RL.*/
struct GM *GMInit(int k, int SP[2], PunPRF *Fp[SPX_D + 1]);

/*The member initialization algorithm return a member,
 generate its secret key sk_ID and the initial state st_ID .*/
struct Mem *MInit(unsigned char ID[ID_SIZE]);

/*A group member ID uses its secret key sk_ID to generate the registration file RF_ID*/
void MRegGen(unsigned char *sk_ID, unsigned char RF_ID[lr][SPX_N]);

/*This algorithm randomly selects an unused mount index*/
struct MountIdx *RandSelect(unsigned char *sk_GM, unsigned char *ID, unsigned char OPK_ID[SPX_N], PunPRF *Fp0);

void mmt_gen_leaves(CacheElement lf[LEAF_NUM], struct RFCa *RFCa_MMT, uint32_t wots_addr[8], const spx_ctx *ctx, PunPRF *Fp0);
void M_Build(MoMST *MMT_sTI, CacheElement lf[LEAF_NUM], const spx_ctx *ctx, uint32_t tree_addr[8]);
void M_GetPrf(unsigned char *pf_lf_sMI, MoMST *MMT_sTI, CacheElement *lf);
int M_Verify(const unsigned char *rt, CacheElement *lf, const unsigned char *pf_lf_sMI, const spx_ctx *ctx, uint32_t tree_addr[8]);
MoMST *Join(unsigned char *sk_GM, struct state_GM *st_GM, unsigned char *ID, unsigned char RF_ID[SPX_N], long T,
            PunPRF *Fp[SPX_D + 1], struct MMT_Sig *Sig_sMI_GM, unsigned char cache[SPX_D][KEY_SIZE * LEAF_NUM]);

/*The signing algorithm takes as input the secret key sk_ID of ID, along with their state st_ID at the current time T, and a message m ∈ M. 
The algorithm generates a group signature SIG on the message m 
and also outputs an updated secret key sk'_ID and state st'_ID , for ID.*/
void Sign(unsigned char *SIG, unsigned char *sk_ID, struct state_ID *st_ID, long T, const unsigned char *m, uint32_t mlen);

/*The signature verification algorithm takes as input 
 the group public key gpk,the revocation list RL, a message m,the used mount index MI, a group signature SIG on m generated at time T,
 It outputs 1 if the signature is valid, and 0 otherwise.*/
int Verify(struct GM *GM1, const unsigned char *m, uint32_t mlen, uint64_t sTI, uint32_t wots_sign_leaf, const unsigned char *SIG, long T);

/*The opening algorithm takes as input 
 the group public key gpk, the group secret key sk_GM at T, a message m, the used mount index MI and a group signature SIG for m,
 return an identity ID or NULL pointer to indicate failure.*/
unsigned char *Open(struct GM *GM1, const unsigned char *m, uint32_t mlen, uint64_t sTI, uint32_t wots_sign_leaf, unsigned char *SIG, long T);

/*The revocation algorithm takes as input 
 the group public key gpk, the group secret key sk_GM at T, the revocation list RL, 
 the revoking identity ID, a group signatures RSS to be revoked. and the used mount index MI,
 This algorithm updates the revocation list RL to RL′.*/
void Revoke(struct GM *GM1, unsigned char *ID, unsigned char *RSS, uint32_t mlen, uint64_t sTI, uint32_t wots_sign_leaf, long T);