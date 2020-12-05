/*
 * Implementation of ISG Attack on K2SN-MSS
 * Author: Roland Booth
*/

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
//   u8 *bytes: byte array to increment
//   int num_bytes: length of byte array
int increment_bytes(u8 *bytes, int num_bytes){
	for (int i = 0; i < num_bytes; i++) {
		if (++bytes[i] != 0x00) {
			break;
		}
	}
}

// Allocation function for adding ksnmss_sig to a gdsl bstree
// Params:
//   void * sig: pointer to ksnmss_sig to add to bstree
// Return:
//   gdsl_element_t: pointer to ksnmss_sig in the tree
gdsl_element_t KSNMSS_Signature_Alloc(void * sig){
	void *ptr = malloc(sizeof(ksnmss_sig));
	memcpy(ptr, sig, sizeof(ksnmss_sig));
	return ptr;
}

// Free function for freeing ksnmss_sig from gdslbstree
// Params: 
//   gdsl_element_t E: pointer to ksnmss_sig to remove
void KSNMSS_Signature_Free(gdsl_element_t E) {
	free(E);
}

// Compare function to compare ksnmss_sig elements in bstree. Only compares ksnmss_sig.sksum member,
//  and ignores the rest of the signature.
// Params:
//   const gdsl_element_t E: pointer to ksnmss_sig
//   void* VALUE: pointer to ksnmss_sig
// Return:
//   long int: 0 if sksum of E and VALUE are equal, >0 if E > VALUE, and <0 if E < VALUE
long int KSNMSS_Signature_Cmp(const gdsl_element_t E, void* VALUE) {
	return (long int) memcmp(((ksnmss_sig *) E)->sksum, ((ksnmss_sig *)VALUE)->sksum, sklen*8);
}

// Performs one invocation of the ISG Attack. Simulates invoking the ISG Attack multiple times
//   using multiple (smaller) values of the ISG Attack parameter g by recording intermediate results
//   of the attack at multiple checkpoints during the Secret-Guessing phase. Records the 
//   intermediate runtime at each checkpoint, which guess the attack succeeded on if it succeeded, 
//   and the amount of memory used to store the set of oracle signature queries (which is the same 
//   for each simulated parameter set).
// Params:
//   ISG_Attack_Result* attack_result: struct containing to store the results of this attack
//   long num_oracle_queries: isg attack parameter q, the number of times the attacker queries the 
//     oracle for a signature
//   long num_sk_guesses: multiple values of isg attack parameter g. Runtime for each value of g
//     is recorded. Assumes array is of length num_runtime_checkpoints. Assumes values of g are in 
//     ascending order.
//   int num_runtime_checkpoints: number of intermediate runtime checkpoints and length of 
//     num_sk_guesses.
void isg_attack(ISG_Attack_Result* attack_result, long num_oracle_queries, long num_sk_guesses[],
                  int num_runtime_checkpoints){
	// *** Setup ***

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

	//Generate random message which will be signed by signing oracle
	u8 M[msglen];
	for (i = 0; i < msglen; i++) M[i] = rand() % 256;

	//Set up empty binary search tree which uses the KSNOTS signature comparison function to test 
	//  for node-equality
	struct gdsl_bstree *sig_tree = gdsl_bstree_alloc("", &KSNMSS_Signature_Alloc, 
													   &KSNMSS_Signature_Free, 
													   &KSNMSS_Signature_Cmp);

	//Initialize success of attack to failure
	attack_result->success_guess = -1;

	//Start timer
	clock_t temp_time;
	clock_t uncounted_time = 0;
	clock_t attack_start_time = clock();

	// *** Query Phase ***
	if (debug) {
		printf("   ---STARTING ATTACK---\n");
		printf("   ---QUERY PHASE---\n");
	}
	ksnmss_sig mss_sig;

	//Query signing oracle for signature for message M multiple times. (Specifically, q times)
	for (u32 query_index = 0; query_index < num_oracle_queries; query_index++) {
		memset(&mss_sig, 0, sizeof(ksnmss_sig));

		//Query signing oracle for K2SN-MSS message. Time spent querying oracle is not counted 
		//towards runtime
		temp_time = clock();
		ksnmss_sign(query_index, M, &mss_sig);
		uncounted_time += clock() - temp_time;

		//Add the k2snmss signature to the tree, indexed by the value of the k2snmss signature's 
		//  ksnots signature
		int bstree_result;
		gdsl_bstree_insert(sig_tree, &mss_sig, &bstree_result);
	}

	// *** Secret-Guessing Phase ***
	if (debug) {
		printf("   ---SECRET-GUESSING PHASE---\n");
	}

	//Initialize s to 0
	u8 ots_sk_guess[seedlen];
	memset(ots_sk_guess, 0, seedlen);

	//Main loop of secret-guessing phase
	u8 ots_sig_guess[sklen * 8];
	int iteration_counter = 0;
	int has_succeeded = 0;
	int next_checkpoint_index = 0;
	// Iterate up to g_max times, where g_max is the largest g parameter we are testing, unless the 
	// attack succeeds before that point in which case we stop iterating immediately 
	while (iteration_counter < num_sk_guesses[num_runtime_checkpoints-1] && !has_succeeded) {

		//Compute KSN-OTS signature of M using OTS sk guess as the secret key
		KSNOTS_sign(ots_sk_guess, M, ots_sig_guess);

		//Search the binary tree for a K2SN-MSS signature which contains the same KSN-OTS signature
		ksnmss_sig temp_mss_sig;
		memcpy(temp_mss_sig.sksum, ots_sig_guess, sklen * 8);
		gdsl_element_t found_element = gdsl_bstree_search(sig_tree, NULL, &temp_mss_sig);

		if (found_element != NULL) {
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
				has_succeeded = 1;

				//Record iteration of secret guessing phase loop that attack succeeded on
				attack_result->success_guess = iteration_counter;
			}
		}

		//Increment secret key guess to next value to guess
		increment_bytes(ots_sk_guess, seedlen);

		iteration_counter++;

		//If this iteration is a checkpoint or the attack succeeded then we record the current 
		//runtime
		if (iteration_counter == num_sk_guesses[next_checkpoint_index] || has_succeeded) {
			//Current runtime
			temp_time = (clock() - attack_start_time) - uncounted_time;

			// If attack succeeded, the runtime of all the remaining checkpoints is the current
			// runtime
			if (has_succeeded) {
				for (int i = next_checkpoint_index; i < num_runtime_checkpoints; i++) {
					attack_result->intermediate_runtimes[i] = temp_time;
				}
			//Otherwise, we only record the intermediate runtime at this iteration and move on
			} else {
				attack_result->intermediate_runtimes[next_checkpoint_index] = temp_time;
				next_checkpoint_index++;
			}
		}
	}

	// *** Cleanup ***
	// Memory usage is the size of 
	attack_result->memory_usage = num_oracle_queries * sizeof(ksnmss_sig);

	// Record number of checkpoints
	attack_result->num_runtime_checkpoints = num_runtime_checkpoints;

	//Destroy binary search tree that stores oracle queries
	gdsl_bstree_free(sig_tree);

	if (debug) {
		printf("\t---ATTACK COMPLETE---\n");
		printf("\tPrinting attack results:\n");
		printf("\t\tNumber of checkpoints:\t%d\n", attack_result->num_runtime_checkpoints);
		printf("\t\tIntermediate runtimes:\t%ld\n", attack_result->intermediate_runtimes[0]);
		for (int i = 1; i < attack_result->num_runtime_checkpoints; i++) {
			printf("\t\t\t\t\t%ld\n", attack_result->intermediate_runtimes[i]);
		}
		printf("\t\tSuccess guess (-1 indicates failure):\t%ld\n", attack_result->success_guess);
		printf("\t\tMemory usage:\t%ld\n", attack_result->memory_usage);
	}
	return;
}

// Invokes the ISG Attack multiple times using one parameter set. Each ISG Attack invocation 
//   simulates invoking the ISG Attack multiple times using multiple (smaller) values of the ISG 
//   Attack parameter g by recording intermediate results of the attack at multiple checkpoints 
//   during the Secret-Guessing phase. Records the average runtime at each intermediate checkpoint, 
//   the percentage of attacks that succeeded before each checkpoint, and the average amount of 
//   memory used to store the set of oracle signature queries (which is the same for each simulated 
//   parameter set).
// Assumes that u8 *num_sk_guesses is a byte array of length seedlen representing an unsigned 
//   integer.
// Params:
//   ISG_Attack_Test_Result* test_results: results of this test
//   long reduced_sk_size: the (reduced) size of secret KSN-OTS keys in bits
//   long num_sk_guesses: multiple values of isg attack parameter g. Runtime after each value of g
//     is recorded. Assumes array is of length num_runtime_checkpoints. Assumes values of g are in 
//     ascending order.
//   long num_sk_guesses: multiple values of isg attack parameter g. Average runtime for each value 
//     of g is recorded. Assumes array is of length num_runtime_checkpoints. Assumes values of g are
//     in ascending order.
//   int num_runtime_checkpoints: number of intermediate runtime checkpoints and length of 
//     num_sk_guesses.
//   int num_attack_iterations: number of invocations of isg_attack()
void isg_attack_test(ISG_Attack_Test_Result* test_result, long reduced_sk_size, 
                       long num_oracle_queries, long num_sk_guesses[], int num_runtime_checkpoints,
                       int num_attack_iterations){
	//Set up K2SN-MSS implementation before it can be used
	//Seed the random number generator
	//(Note - srand is not cryptographically suitable, but for the purpose of this test it is 
	//  sufficient)
	srand(time(0));
	//Precompute entire table of binomial coefficients, used in CFF computation.
	set_binotable();
	
	//Set value of global variable for secret ots key size
	chopped_key_size = reduced_sk_size;

	//Ensure compiler does not optimize away pointer
	ISG_Attack_Result single_attack_results;
	//Running runtimes at each checkpoint, number of successes before each checkpoint, and memory 
	//usage
	long long intermediate_runtime_sums[num_runtime_checkpoints];
	for (int i = 0; i < num_runtime_checkpoints; i++){
		intermediate_runtime_sums[i] = 0;
	}
	long intermediate_success_sums[num_runtime_checkpoints];
	for (int i = 0; i < num_runtime_checkpoints; i++){
		intermediate_success_sums[i] = 0;
	}
	long long memory_usage_sum = 0;

	//Invoke ISG Attack num_attack_iterations times and keep running total of results
	for (int i = 0; i < num_attack_iterations; i++) {
		if (debug) {
			printf("\n---START ATTACK No. %d---\n", i);
		}

		isg_attack(&single_attack_results, num_oracle_queries, num_sk_guesses, 
				     num_runtime_checkpoints);
		if (debug) {
			printf("---END ATTACK No. %d---\n", i);
		}
		//Add to running totals of results
		for (int i = 0; i < num_runtime_checkpoints; i++) {
			intermediate_runtime_sums[i] += single_attack_results.intermediate_runtimes[i];
			if (single_attack_results.success_guess < num_sk_guesses[i] && 
			      single_attack_results.success_guess >= 0) {
				intermediate_success_sums[i]++;
			}
		}
		memory_usage_sum += single_attack_results.memory_usage;
	} 

	//Calculate average runtimes, success probabilities, and memory usage
	test_result->num_runtime_checkpoints = num_runtime_checkpoints;
	for (int i = 0; i < num_runtime_checkpoints; i++) {
		test_result->average_intermediate_runtimes[i] = ((long double) intermediate_runtime_sums[i])
		  / ((long double) num_attack_iterations);
		test_result->average_intermediate_successes[i] = ((double) intermediate_success_sums[i]) /
		  ((double) num_attack_iterations);
	}
	test_result->average_memory_usage = ((long double) memory_usage_sum) / ((long double)
	  num_attack_iterations);
	
	return;
}

// Invokes ISG Attack test using command line parameters, or default parameters if command line 
//   parameters are not given.
// Params (from command line):
//   int: Debug mode on or off. (0 for debug off, 1 for degub on)
//   int: Number of ISG Attack iterations in test
//   int: Size of chopped keys in bits
//   int: log(q), where q is the number of signing oracle queries in an ISG Attack iteration
//   int (1 or more): 1 or more values of log(g). Must be in ascending order
int main(int argc, char *argv[]) {
	int num_attack_iterations, log_q, log_g_s[MAX_NUM_CHECKPOINTS], num_checkpoints;

	//Set test parameters with command line arguments, otherwise use default parameters
	if (argc >= 5) {
		debug = atoi(argv[1]);
		num_attack_iterations = atoi(argv[2]);
		chopped_key_size = atoi(argv[3]);
		log_q = atoi(argv[4]);
		num_checkpoints = argc - 5;
		for (int i = 0; i < num_checkpoints; i++) {
			log_g_s[i] = atoi(argv[i + 5]);
		}
	} else {
		debug = 0;
		num_attack_iterations = 4;
		chopped_key_size = 2;
		log_q = 2;
		num_checkpoints = 3;
		log_g_s[0] = 0;
		log_g_s[1] = 2;
		log_g_s[2] = 4;
	}
	
	long num_oracle_queries = 0x01 << log_q;
	long num_sk_guesses[MAX_NUM_CHECKPOINTS];
	for (int i = 0; i < num_checkpoints; i++) {
		num_sk_guesses[i] = 0x01 << log_g_s[i];
	}
	ISG_Attack_Test_Result test_result;

	printf("---TEST PARAMETERS---\n");
	printf("\tChopped key size (bits):\t%d\n", chopped_key_size);
	printf("\tNumber of oracle queries:\t%ld\n", num_oracle_queries);
	printf("\tNumber of checkpoints:\t\t%d\n", num_checkpoints);
	printf("\tNumber of secret-guesses:\t%ld", num_sk_guesses[0]);
	for (int i = 1; i < num_checkpoints; i++) {
		printf(", %ld", num_sk_guesses[i]);
	}
	printf("\n");
	printf("\tNumber of attack iterations:\t%d\n", num_attack_iterations);

	printf("\n---STARTING TEST---\n");
	//Record the real time of the test
	int test_start_time = clock();

	//Run test
	isg_attack_test(&test_result, chopped_key_size, num_oracle_queries, num_sk_guesses, 
					  num_checkpoints, num_attack_iterations);

	int test_end_time = clock();

	//Print test results
	printf("\n---TEST COMPLETE---\n");
	printf("Printing test results:\n");
	printf("\tAverage runtimes (clock ticks, seconds):\t%Lf, %Lf\n", 
	         test_result.average_intermediate_runtimes[0], 
			 test_result.average_intermediate_runtimes[0] / ((long double) CLOCKS_PER_SEC));
	for (int i = 1; i < test_result.num_runtime_checkpoints; i++) {
		printf("\t\t\t\t\t\t\t%Lf, %Lf\n", test_result.average_intermediate_runtimes[i], 
			     test_result.average_intermediate_runtimes[i] / ((long double) CLOCKS_PER_SEC));
	}
	printf("\tSuccess probabilities:\t%lf\n", test_result.average_intermediate_successes[0]);
	for (int i = 1; i < test_result.num_runtime_checkpoints; i++) {
		printf("\t\t\t\t%lf\n", test_result.average_intermediate_successes[i]);
	}
	printf("\tMemory usage (in bytes):\t%Lf\n", test_result.average_memory_usage / ((long long) 8));
	printf("\tTest real time (seconds):\t%lf\n", ((double) (test_end_time - test_start_time)) / 
	         (double) CLOCKS_PER_SEC);

	return 0;
}
