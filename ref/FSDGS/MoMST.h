#include "../params.h"

#define AES_GCM_CIPHERTEXT_SIZE (CIPHERTEXT_SIZE+16)
#define MAX_LEAF_NUM (1<<(SPX_TREE_HEIGHT-1))

typedef struct CacheElement {
    unsigned int leaf_index;              // the index for the leaf
    unsigned char leaf_value[SPX_N];  // SHAKE hash of the leaf value
    unsigned char OPK[SPX_N];            // WOTS+ OTS public key (OPK)
    unsigned char ciphertext1[AES_GCM_CIPHERTEXT_SIZE]; // AES-GCM-SIV ciphertext 1
    unsigned char ciphertext2[AES_GCM_CIPHERTEXT_SIZE]; // AES-GCM-SIV ciphertext 2
    struct CacheElement *next; // Pointer to the next element in the linked list
} CacheElement;

typedef struct MoMST {
    uint64_t sTI;       //the tree_idx of the MoMST tree
    unsigned char* Rt;  //the root of the MoMST tree
    unsigned char inner_node[SPX_TREE_HEIGHT][MAX_LEAF_NUM][SPX_N];  // inner node of the MoMST tree
    CacheElement *leaves;  // Linked list of leaf nodes
} MoMST;

