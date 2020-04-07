#include "K2SN-MSS/measurement.h"
#include <time.h>
#include "K2SN-MSS/merkle-tree.h"
#include "K2SN-MSS/ChaCha20/chacha.c"
#include "K2SN-MSS/swifft16/swifft-avx2-16.c"
#include "K2SN-MSS/ksnmss.c"
#include <x86intrin.h>
#include "main.h"

// Treats byte array as a large unsigned integer and increments its value by 1
// Params:
//  u8 *bytes: byte array to increment
//  int num_bytes: length of byte array
int increment_bytes(u8 *bytes, int num_bytes){
	for (int i = 0; i < num_bytes; i++) {
		if (++bytes[i] != 0x00) {
			break;
		}
	}
}

// Allocation function for adding ksnmss_sig to a gdsl bstree
// Params:
//  void * sig: pointer to ksnmss_sig to add to bstree
// Return:
//  gdsl_element_t: pointer to ksnmss_sig in the tree
gdsl_element_t KSNMSS_Signature_Alloc(void * sig){
	void *ptr = malloc(sizeof(ksnmss_sig));
	memcpy(ptr, sig, sizeof(ksnmss_sig));
	return ptr;
}

// Free function for freeing ksnmss_sig from gdslbstree
// Params: 
//  gdsl_element_t E: pointer to ksnmss_sig to remove
void KSNMSS_Signature_Free(gdsl_element_t E) {
	free(E);
}

// Compare function to compare ksnmss_sig elements in bstree. Only compares ksnmss_sig.sksum member, and ignores the rest of
//  the signature.
// Params:
//  const gdsl_element_t E: pointer to ksnmss_sig
//  void* VALUE: pointer to ksnmss_sig
// Return:
//  long int: 0 if sksum of E and VALUE are equal, >0 if E > VALUE, and <0 if E < VALUE
long int KSNMSS_Signature_Cmp(const gdsl_element_t E, void* VALUE) {
	return (long int) memcmp(((ksnmss_sig *) E)->sksum, ((ksnmss_sig *)VALUE)->sksum, sklen*8);
}

// Performs one invocation of the ISRA attack. Assumes that u8 *num_sk_guesses is a byte array of length seedlen representing 
//  an unsigned integer.
// Params:
//  ISRA_Attack_Result* attack_result: struct containing to store the results of this attack
//  int num_oracle_queries: isra parameter q, the number of times the attacker queries the oracle for a signature
//  u8 *num_sk_guesses: isra parameter Q, the number of guesses the attacker makes in the guessing phase
void isra_attack(ISRA_Attack_Result *attack_result, int num_oracle_queries, u8 *num_sk_guesses) {
	//Initially set success of attack to failure
	(attack_result)->success = 0;

	//---Set up signing oracle---
	//Generate seeds and ivs for all three seeds
	int i;
	//Seed the random number generator
	srand(time(NULL));
	for (i = 0; i < seedlen; i++) system_seed[i] = rand() % 255;
	for (i = 0; i < ivlen; i++) system_iv[i] = rand() % 255;
	for (i = 0; i < seedlen; i++) randompad_seed[i] = rand() % 255;
	for (i = 0; i < ivlen; i++) randompad_iv[i] = rand() % 255;
	for (i = 0; i < seedlen; i++) hk_seed[i] = rand() % 255;
	for (i = 0; i < ivlen; i++) hk_iv[i] = rand() % 255;

	//Generate public and private key pair
	key_generation(system_seed, system_iv);

	//---ISRA Attack setup phase---
	//Start timer
	clock_t attack_start_time, attack_end_time, query_start_time, query_end_time, query_time_total, attack_time_total;
	attack_start_time = clock();

	//Generate random message which will be signed by signing oracle
	u8 M[msglen];
	for (i = 0; i < msglen; i++) M[i] = rand() % 256;

	//Set up empty binary search tree which uses the KSNOTS signature comparison function to test for node-equality
	struct gdsl_bstree *sig_tree = gdsl_bstree_alloc("", &KSNMSS_Signature_Alloc, &KSNMSS_Signature_Free, &KSNMSS_Signature_Cmp);

	//---ISRA Attack Query Phase---
	printf("   ---STARTING ATTACK---\n");
	printf("   ---QUERY PHASE---\n");
	ksnmss_sig mss_sig;

	//Query signing oracle for signature for message M multiple times. (Specifically, q times)
	query_time_total = 0;
	for (u32 query_index = 0; query_index < num_oracle_queries; query_index++) {
		memset(&mss_sig, 0, sizeof(ksnmss_sig));

		//Query signing oracle for K2SN-MSS message, keeping track of time spent on queries so it can be subtracted from the attack's time
		query_start_time = clock();
		ksnmss_sign(query_index, M, &mss_sig);
		query_end_time = clock();
		query_time_total = query_time_total + (query_end_time - query_start_time);

		//Add the k2snmss signature to the tree, indexed by the value of the k2snmss signature's ksnots signature
		int bstree_result;
		gdsl_bstree_insert(sig_tree, &mss_sig, &bstree_result);
	}

	//---ISRA Attack Secret-Guessing Phase---
	printf("   ---SECRET-GUESSING PHASE---\n");

	//Initialize s to 0
	u8 ots_sk_guess[seedlen];
	memset(ots_sk_guess, 0, seedlen);

	//Main loop of secret guessing phase
	u8 ots_sig_guess[sklen * 8];
	int iteration_counter = 0;
	do {
		//Compute KSN-OTS signature of M using OTS sk guess as the secret key
		KSNOTS_sign(ots_sk_guess, M, ots_sig_guess);

		//Search the binary tree for a K2SN-MSS signature which contains the same KSN-OTS signature
		ksnmss_sig temp_mss_sig;
		memcpy(temp_mss_sig.sksum, ots_sig_guess, sklen * 8);
		gdsl_element_t found_element = gdsl_bstree_search(sig_tree, NULL, &temp_mss_sig);
		// if (!IsFointAbstractError(pointer_mss_sig_guess)) {
		if (found_element != NULL) {
			// printf("      Found forged signature in S on iteration: %d\n", iteration_counter);
			// printf("      The K2SN-MSS index of the forged signature is: %d\n", ((ksnmss_sig *) found_element)->id);
			//Choose new message - we will forge a signature for this message
			u8 M_F[msglen];
			do {
				for (i = 0; i < msglen; i++) M[i] = rand() % 256;
			} while (memcmp(M_F, M, msglen) == 0);
		
			//Forge KSN-OTS signature of M_F
			u8 ots_sig_M_F[sklen * 8];
			KSNOTS_sign(ots_sk_guess, M_F, ots_sig_M_F);

			//If forged OTS siganture is valid, forge a K2SN-MSS signature
			if (KSNOTS_verify(((ksnmss_sig *) found_element)->pk, M_F, ots_sig_M_F, 
					((ksnmss_sig *) found_element)->id)) { 
				//Construct K2SN-MSS forger of M_F
				ksnmss_sig mss_sig_M_F;
				mss_sig_M_F.id = ((ksnmss_sig *) found_element)->id;
				memcpy(mss_sig_M_F.message, M_F, msglen);
				memcpy(mss_sig_M_F.sksum, ots_sig_M_F, sklen * 8);
				memcpy(&mss_sig_M_F.pk, ((ksnmss_sig *) found_element)->pk, t * pklen);
				memcpy(&mss_sig_M_F.auth, ((ksnmss_sig *) found_element)->auth, h * pklen);

				//Attack is successful
				(attack_result)->success = 1;

				//End attack
				goto exitSecretGuessingPhase;
			}
		}

		//Increment secret key guess to next value to guess
		increment_bytes(ots_sk_guess, seedlen);

		//If we have tested more than num_sk_guesses keys, end the loop
		i = seedlen - 1;
		while (i >= 0 && ots_sk_guess[i] == num_sk_guesses[i]) {
			i--;
		}
		iteration_counter++;
	} while(ots_sk_guess[i] < num_sk_guesses[i]);
	exitSecretGuessingPhase:

	//--- Attack is complete ---
	//End timer
	attack_end_time = clock();
	attack_time_total = (attack_end_time - attack_start_time) - query_time_total;
	(*attack_result).runtime = attack_time_total;

	printf("   ---ATTACK COMPLETE---\n");


	printf("   Printing attack results:\n");
	printf("      Runtime (clock ticks): %ld\n", (*attack_result).runtime);
	printf("      Success (1 is success, 0 is failure): %d\n", (*attack_result).success);
	return;
}

// Performs one test of the isra_attack(). A test invokes the isra_attack multiple times for one parameter set, and calculates the average
//  runtime and success probability of the isra_attack(). Assumes that u8 *num_sk_guesses is a byte array of length seedlen representing 
//  an unsigned integer.
// Params:
//  ISRA_Attack_Test_Result* test_results: struct to store the results of this test
//  int reduced_sk_size: the (reduced) size of secret KSN-OTS keys in bits
//  int num_oracle_queries: isra parameter q, the number of times the attacker queries the oracle for a signature
//  u8 *num_sk_guesses: isra parameter Q, the number of guesses the attacker makes in the guessing phase
//  int num_attack_iterations: number of invocations of the isra_attack
void isra_attack_test(ISRA_Attack_Test_Result* test_result, int reduced_sk_size, int num_oracle_queries, u8 *num_sk_guesses, int num_attack_iterations) {
	//Set up K2SN-MSS implementation before it can be used
	//Seed the random number generator
	//(Note - srand is not cryptographically suitable, but for the purpose of this test it is sufficient)
	srand(time(0));
	//Precompute entire table of binomial coefficients, used in CFF computation.
	set_binotable();
	
	//Set value of global variable for secret ots key size
	chopped_key_size = reduced_sk_size;

	ISRA_Attack_Result single_attack_results;
	//Running total of number of success and total runtime
	int runtime_sum = 0;
	int success_sum = 0;

	//Invoke isra attack num_attack_iterations times and keep running total of results
	for (int i = 0; i < num_attack_iterations; i++) {
		printf("\n---START ATTACK No. %d---\n", i);
		isra_attack(&single_attack_results, num_oracle_queries, num_sk_guesses);
		printf("---END ATTACK No. %d---\n", i);
		runtime_sum += single_attack_results.runtime;
		if (single_attack_results.success) {
			success_sum++;
		}
	} 

	//Calculate average runtime and success probability
	(*test_result).average_runtime = ((double) runtime_sum) / ((double) num_attack_iterations);
	(*test_result).average_success = ((double) success_sum) / ((double) num_attack_iterations);
	
	return;
}


int main(int argc, char *argv[]){
	int num_attack_iterations, log_Q, log_q;

	//Set test parameters with command line arguments, otherwise use default parameters
	if (argc >= 5) {
		num_attack_iterations = atoi(argv[1]);
		chopped_key_size = atoi(argv[2]);
		log_Q = atoi(argv[3]);
		log_q = atoi(argv[4]);
	} else {
		num_attack_iterations = 4;
		chopped_key_size = 6;
		log_Q = 4;
		log_q = 2;
	}
	
	int num_oracle_queries = 0x01 << log_q;
	u8 num_sk_guesses[seedlen];
	ISRA_Attack_Test_Result test_result;
	memset(num_sk_guesses, 0, seedlen);
	num_sk_guesses[log_Q / 8] = 0x01 << (log_Q % 8);

	printf("---TEST PARAMETERS");
	printf("   Chopped key size (bits): %d\n", chopped_key_size);
	printf("   Number of oracle queries: %d\n", num_oracle_queries);
	printf("   Number of secret-guesses: %d\n", 0x01 << log_Q);
	printf("   Number of attack iterations: %d\n", num_attack_iterations);

	printf("\n---STARTING TEST---\n");
	int test_start_time = clock();
	isra_attack_test(&test_result, chopped_key_size, num_oracle_queries, num_sk_guesses, num_attack_iterations);
	int test_end_time = clock();
	printf("\n---TEST COMPLETE---\n");
	printf("Printing test results:\n");
	printf("   Average runtime: %lf clock ticks (%lf seconds)\n", test_result.average_runtime, 
		test_result.average_runtime / ((double) CLOCKS_PER_SEC));
	printf("   Success probability: %lf\n", test_result.average_success);
	printf("   Test real time (seconds): %lf\n", ((double) (test_end_time - test_start_time)) / (double) CLOCKS_PER_SEC);

	return 0;
}
