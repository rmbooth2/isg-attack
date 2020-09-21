#include <stdlib.h>
#include "chacha.c"

#define len 32

void print_ECRYPT_ctx(ECRYPT_ctx *x);


int main(){
	u8 one[64]={1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	u8 two[64]={2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	u8 ch1[64];
	u8 ch2[64];//={2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};;
	u8 prime_key[len];//={192, 3, 137, 61, 252, 127, 87, 32, 16, 39, 207, 192, 100, 127, 42, 45, 8, 154, 38, 56, 56, 67, 32, 54, 239, 65, 173, 192, 100, 127, 50, 70};
	u8 iv[8];
	u8 key[len];
	ECRYPT_ctx seed_ctx;
	int i;
	
	//u32 kbits=256;
	//u32 ivbits=64;


	for(i=0;i<len;i++) prime_key[i]=rand()%255;
	for(i=0;i<len;i++) iv[i]=rand()%255;
	printf("SEED\n");
	for(i=0;i<len;i++) printf("%hhu ",prime_key[i]);
	printf("\n=============================================\n");
	
	ECRYPT_keysetup(&seed_ctx,prime_key,256,64);
	ECRYPT_ivsetup(&seed_ctx,iv);
	ECRYPT_encrypt_bytes(&seed_ctx,one,ch1,64);
	//ECRYPT_keysetup(&sd,seed,256,64);
	ECRYPT_encrypt_bytes(&seed_ctx,two,ch2,64);
	printf("\nONE====================\n");
	for(i=0;i<64;i++) printf("%hhu ",ch1[i]);
	printf("\ntwo====================\n");
	for(i=0;i<64;i++) printf("%hhu ",ch2[i]);
	printf("\n");
	
	return 0;
}

void print_ECRYPT_ctx(ECRYPT_ctx *x){
	for (int i=0; i< 16; i++)
		printf("%u ",x->input[i]);
	printf("\n");
}
