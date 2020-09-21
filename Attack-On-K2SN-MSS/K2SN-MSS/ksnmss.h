#ifndef KSNMSS_H_
#define KSNMSS_H_


#include "merkle-tree.c"
#include "1cff.c"

#define seedlen 32
#define msglen 32
#define ivlen 8

//Size of the shortened secret KSN-OTS keys in bits
int chopped_key_size;

int updateiter = h/2-1;
u8 system_seed[seedlen];
u8 system_iv[ivlen];	
u8 randompad_seed[seedlen];
u8 randompad_iv[ivlen];

sk_node random_pad[h+l];
node auth[h];
node keep[h-1];
node retain;
node MSSPK;

typedef struct signature{
	u32 id;
	u8 message[msglen];
	u8 sksum[sklen*8];
	node pk[t];
	node auth[h];
}ksnmss_sig;


typedef struct rg_elm{
	u32 key[rglen];
}rg_elm;

const u8 enc_one[sklen]={1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
const u8 enc_two[sklen]={2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
       	    	     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

// Assumes ots_key is an array of length seedlen
// Zeros every bit of ots_key except the least significant num_remaining_bits bits
void chop(u8 *ots_key, int num_remaining_bits);

// Computes KSN-OTS signature
// Params:
//  u8 *OTS_sk: secret OTS key. Assumes this is an array of length seedlen
//  u8 *ms:	message to sign
//  u8 *sksum: Pointer to array which will be filled with signature. Assumes lenght of *sksum is (sklen * 8)
void KSNOTS_sign(u8 *OTS_sk, u8 *ms, u8 *OTS_signature);

// Verifies KSN-OTS signature
// Params:
//  node *OTS_pk: public OTS key. Assumes this is an array of length seedlen
//  u8 *ms:	message to sign
//  u8 *OTS_signature: Pointer to array which will be filled with signature. Assumes lenght of *sksum is (sklen * 8)
//  u32 instance_index: index of KSN-OTS instance used to verify signature - used to compute the gSWIFFT key
// Return: 1 if signature is valid, negative number otherwise
int KSNOTS_verify(node *OTS_pk, u8 *ms, u8 *OTS_signature, u32 instance_index);

void system_setup();
void generate_secret_key_OTS(ECRYPT_ctx *seed_ctx, u8 *idu8, sk_node *sk);
void generate_public_key_OTS(sk_node *sk, node *pk, vec A[16][4]);
void key_generation(u8 *system_seed, u8 *system_iv);
node create_L_tree(node *pk, u32 id);
void pn(node *r);

void ksnmss_sign(u32 id, u8 *ms, ksnmss_sig *sig);
int ksnmss_verify(u32 id, u8 *ms, ksnmss_sig *sig);
void convert_ring(u8 *rg8, rg_elm *a);
void set_random_pad(u32 indx, u32 height, u8 randpad[sklen]);
#endif
