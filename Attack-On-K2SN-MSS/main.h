/*
 * Implementation of ISG Attack on K2SN-MSS
 * Author: Roland Booth
*/

#include <gdsl.h>

// Maximum number of checkpoints to record intermediate runtime of attack
#define MAX_NUM_CHECKPOINTS 64

// Flag indicating debug mode on or off
int debug = 0;

//Used to store the results of a single iteration of the ISG Attack
typedef struct {
    // Number of intermediate runtimes that will be recorded. Must be less than MAX_NUM_CHECKPOINTS
    int num_runtime_checkpoints;
    // Intermediate runtimes. i^th element is the intermediate runtime of the i^th checkpoint. Extra
    // elements are 0. Element at index num_runtime_checkpoints-1 is the total runtime of the attack.
    clock_t intermediate_runtimes[MAX_NUM_CHECKPOINTS];
    // Iteration number of the Secret-Guessing phase loop of the guess that succeeded, or -1 if the
    // attack did not succeed
    long success_guess;
    // Memory usage to store set of oracle query signature responses
    long memory_usage;
} ISG_Attack_Result;

//Used to store the results of a test of the ISG Attack
typedef struct {
    // Number of intermediate runtimes that will be recorded. Must be less than MAX_NUM_CHECKPOINTS
    int num_runtime_checkpoints;
    // Average intermediate runtimes at each runtime checkpoint. Extra elements are 0. The element 
    // at index num_runtime_checkpoints-1 is the average total runtime.
    long double average_intermediate_runtimes[MAX_NUM_CHECKPOINTS];
    // Percentage of attacks that succeeded before each intermediate checkpoint as a decimal. Extra 
    // elements are zero. i^th element is the percentage of attacks that succeeded before the i^th
    // checkpoint.
    double average_intermediate_successes[MAX_NUM_CHECKPOINTS];
    // Average memory usage to store set of oracle query signature responses
    long double average_memory_usage;
} ISG_Attack_Test_Result;

// Treats byte array as a large unsigned integer and increments its value by 1
// Params:
//   u8 *bytes: byte array to increment
//   int num_bytes: length of byte array
int increment_bytes(u8 *bytes, int num_bytes);

// Allocation function for adding ksnmss_sig to a gdsl bstree
// Params:
//   void * sig: pointer to ksnmss_sig to add to bstree
// Return:
//   gdsl_element_t: pointer to ksnmss_sig in the tree
gdsl_element_t KSNMSS_Signature_Alloc(void * sig);

// Allocation function for adding ksnmss_sig to a gdsl bstree
// Params:
//   void * sig: pointer to ksnmss_sig to add to bstree
// Return:
//   gdsl_element_t: pointer to ksnmss_sig in the tree
void KSNMSS_Signature_Free(gdsl_element_t E);

// Compare function to compare ksnmss_sig elements in bstree. Only compares ksnmss_sig.sksum member,
//   and ignores the rest of the signature.
// Params:
//   const gdsl_element_t E: pointer to ksnmss_sig
//   void* VALUE: pointer to ksnmss_sig
// Return:
//   long int: 0 if sksum of E and VALUE are equal, >0 if E > VALUE, and <0 if E < VALUE
long int KSNMSS_Signature_Cmp(const gdsl_element_t E, void* VALUE);

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
                  int num_runtime_checkpoints);

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
                       int num_attack_iterations);
