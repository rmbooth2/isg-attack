#include "measurement.h"
#include <time.h>
#include "merkle-tree.h"
#include "ChaCha20/chacha.c"
#include "swifft16/swifft-avx2-16.c"
#include "ksnmss.c"
#include <x86intrin.h>


int main(){
	int i,j;
	
	//Seed the random number generator
	srand(time(0));

	//Generate seeds and ivs for all three seeds
	printf("Initializing system seeds... ");	
	for(i=0;i<seedlen;i++) system_seed[i]=rand()%255;
	for(i=0;i<ivlen;i++) system_iv[i]=rand()%255;
	for(i=0;i<seedlen;i++) randompad_seed[i]=rand()%255;
	for(i=0;i<ivlen;i++) randompad_iv[i]=rand()%255;
	for(i=0;i<seedlen;i++) hk_seed[i]=rand()%255;
	for(i=0;i<ivlen;i++) hk_iv[i]=rand()%255;


	//Precompute entire table of binomial coefficients, used in CFF computation.
	set_binotable();	
	printf("Finished.\n");
	
	//Generate public and private key pair
	printf("Key Generation Phase... ");
	key_generation(system_seed, system_iv);
	printf("Finished.\n");

	//Generate random message and sign it once with every OTS instance
	printf("Signing %d messages... ", usr);
	u32 id;
	u8 ms[msglen];
	for(j=0;j<msglen;j++) ms[j]=rand()%256;
	ksnmss_sig sig;
	for(id=0;id<usr;id++)
		ksnmss_sign(id, ms, &sig);
	printf("Finished.\n");

	//Verify all 2^h signatures
	printf("Verifying %d messages... ", usr);
	int verified = 1;
	for(i=0;i<usr;i++)
		verified&=ksnmss_verify(id-1, ms, &sig);
	printf("Finished.\n");
	printf("Verify signatures of all messages: %d\n",verified);
	
	return 0;
}
