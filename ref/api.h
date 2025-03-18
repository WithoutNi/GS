#ifndef SPX_API_H
#define SPX_API_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"
#include "PPRF/PunPRF.h"
#include "AE/AES_GCM_SIV.h"
#include "PRG/prg.h"


#define CRYPTO_ALGNAME "Group Signature"

#define CRYPTO_SECRETKEYBYTES SPX_SK_BYTES
#define CRYPTO_PUBLICKEYBYTES SPX_PK_BYTES
#define CRYPTO_BYTES SPX_BYTES
#define CRYPTO_SEEDBYTES 3*SPX_N

/*
 * Returns the length of a secret key, in bytes
 */
unsigned long long crypto_sign_secretkeybytes(void);

/*
 * Returns the length of a public key, in bytes
 */
unsigned long long crypto_sign_publickeybytes(void);

/*
 * Returns the length of a signature, in bytes
 */
unsigned long long crypto_sign_bytes(void);

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
unsigned long long crypto_sign_seedbytes(void);

/*
 * Generates a SPHINCS+ key pair given a seed.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed,PunPRF* PunPRFi);

/*
 * Generates a SPHINCS+ key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 * Generate a PunPRF instance each layer(from layer 0 to layer d-1) */
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk,PunPRF* PunPRF1[SPX_D+1]);

/**
 * Returns an array containing a detached signature.
 */
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk,PunPRF* PunPRF1[SPX_D+1],unsigned char cache[SPX_D][KEY_SIZE*LEAF_NUM]);

int GetAuth(uint8_t *Auth, size_t *Authlen,
            PunPRF *Fp[SPX_D + 1],uint8_t *sk,
            const uint8_t *m, size_t mlen, 
            uint64_t sTI,unsigned char cache[SPX_D][KEY_SIZE*LEAF_NUM]);

int AuthVrfy(const uint8_t *pk,
             const uint8_t *m, size_t mlen,
             const uint8_t *Auth, size_t Authlen,
             uint64_t sTI);

/**
 * Verifies a detached signature and message under a given public key.
 */
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk);

/**
 * Returns an array containing the signature followed by the message.
 */
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk,PunPRF* PunPRF1[SPX_D+1]);

/**
 * Verifies a given signature-message pair under a given public key.
 */
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);

#endif
