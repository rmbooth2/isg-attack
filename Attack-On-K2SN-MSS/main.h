#include <gdsl.h>

//Used to store the results of a single ISRA attack
typedef struct {
    clock_t runtime;
    int success;
} ISRA_Attack_Result;

//Used to store the results of a ISRA attack test
typedef struct {
    double average_runtime;
    double average_success;
} ISRA_Attack_Test_Result;


// Treats byte array as a large unsigned integer and increments its value by 1
// Params:
//  u8 *bytes: byte array to increment
//  int num_bytes: length of byte array
int increment_bytes(u8 *bytes, int num_bytes);

// Allocation function for adding ksnmss_sig to a gdsl bstree
// Params:
//  void * sig: pointer to ksnmss_sig to add to bstree
// Return:
//  gdsl_element_t: pointer to ksnmss_sig in the tree
gdsl_element_t KSNMSS_Signature_Alloc(void * sig);

// Allocation function for adding ksnmss_sig to a gdsl bstree
// Params:
//  void * sig: pointer to ksnmss_sig to add to bstree
// Return:
//  gdsl_element_t: pointer to ksnmss_sig in the tree
void KSNMSS_Signature_Free(gdsl_element_t E);

// Compare function to compare ksnmss_sig elements in bstree. Only compares ksnmss_sig.sksum member, and ignores the rest of
//  the signature.
// Params:
//  const gdsl_element_t E: pointer to ksnmss_sig
//  void* VALUE: pointer to ksnmss_sig
// Return:
//  long int: 0 if sksum of E and VALUE are equal, >0 if E > VALUE, and <0 if E < VALUE
long int KSNMSS_Signature_Cmp(const gdsl_element_t E, void* VALUE);

// Performs one invocation of the ISRA attack. Assumes that u8 *num_sk_guesses is a byte array of length seedlen representing 
// an unsigned integer.
// Params:
//  ISRA_Attack_Result* attack_result: struct containing to store the results of this attack
//  int num_oracle_queries: isra parameter q, the number of times the attacker queries the oracle for a signature
//  u8 *num_sk_guesses: isra parameter Q, the number of guesses the attacker makes in the guessing phase
void isra_attack(ISRA_Attack_Result* result, int num_oracle_queries, u8 *num_sk_guesses);

// Performs one test of the isra_attack(). A test invokes the isra_attack multiple times for one parameter set, and calculates the average
//  runtime and success probability of the isra_attack(). Assumes that u8 *num_sk_guesses is a byte array of length seedlen representing 
//  an unsigned integer.
// Params:
//  ISRA_Attack_Test_Result* test_results: struct to store the results of this test
//  int reduced_sk_size: the (reduced) size of secret KSN-OTS keys in bits
//  int num_oracle_queries: isra parameter q, the number of times the attacker queries the oracle for a signature
//  u8 *num_sk_guesses: isra parameter Q, the number of guesses the attacker makes in the guessing phase
//  int num_attack_iterations: number of invocations of the isra_attack
void isra_attack_test(ISRA_Attack_Test_Result* test_result, int reduced_sk_size, int num_oracle_queries, u8 *num_sk_guesses, int num_attack_iterations);
