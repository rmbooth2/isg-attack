// Contains functions necessary to run a single iteration of the ISG Attack on a fresh instance of 
// XMSS / XMSS^MT

#include "isg-attack-xmss.h"

// Performs single iteration of the ISG Attack on a fresh instance of XMSS. Records the runtime, 
// success (true /false), and memory usage of the attack.
// Params:
//  unsigned int q: ISG Attack input parameter g. Number of queries to signing oracle in Query 
//  	Phase.
//  unsigned int g: ISG Attack input parameter q. (Maximum) number of internal secret guesses in 
//  	Secret-Guessing Phase
//  unsigned char* m_forgery: ISG Attack parameter M_F. Goal of ISG Attack is to forge a signature 
//  	for this message.
//  XMSSModifiedParameterSet * xmss_params: Set of XMSS / XMSS^MT instance parameters. ISG Attack 
//  	will attack a fresh XMSS / XMSS^MT instance that uses these parameters.
// Return:
//  ISGAttackResult: a struct containing the runtime of the attack in clock cycles, whether the 
//  	attack succeeded, peak memory used by the attack, and (if success) a forged XMSS / XMSS^MT 
//  	signature for the message m_forgery
ISGAttackResult isg_attack_xmss(unsigned int q, unsigned int g, unsigned char* m_forgery, 
	XMSSModifiedParameterSet* xmss_params) {
	// *** PRECOMPUTATIONS ***

	// The purpose of this phase is to prepare everything we need before the Query Phase. This 
	// includes initializing a fresh XMSS instance to attack and preparing to measure runtime and
	// memory usage.
	// Notes on this step:
	// - This step does NOT count towards runtime or memory usage. The timer should begin at the 
	//   beginning or the query phase.

	// Initialize fresh XMSS instance. This step includes:
	// - Running XMSS / XMSS^MT key generation algorithm

	// Initializing tools to measure runtime and memory usage
	// - Initialize tool to measure runtime
	//   - Suggested tool: time.h library. This is the tool that was used in the attack on K2SN-MSS
	//     implementation. The "start time" and "end time" of the attack can be recorded using calls
	//     to clock(). Then, the difference between times can be recorded.
	// - Initialize tool to measure memory usage
	//   - Suggested tool: undecided. See supporting document for further information on memory 

	// (optional) Initialize pseudorrandom number generator
	// - In the attack K2SN-MSS implementation, a (not cryptographically suitable) prng is used to
	//   generate the query message and to seed the K2SN-MSS key generation algorithm. 
	// - Suggested prng is srand() in stdlib.h. While this is not cryptographically suitable in 
	//   in general, it will be sufficient for this attack implementation.

	// Initialize Secret component key Table (SCK Table).
	// - SCK Table is essentially an array of length \ell of binary search trees. The i^th tree 
	//   contains an ordered set of tuples. The first element of the tuple is the i^th secret 
	//   component key of a wots instance. The next element is another secret component key of the 
	//   same wots instance. The remaining elements contain enough information to determine: 1. the 
	//   location of the wots instance in the hyper tree, and 2. the index of the other secret 
	//   component key. The tuple is keyed by the value of the i^th secret component key.
	// - Suggested way to implement: an array of length \ell where each element of the array is a
	//   gdls binary search tree. If the glds implementation is used for binary search trees, then 
	//   the functions SCK_table_tuple_alloc, SCK_table_tuple_free and SCK_table_tuple_cmp must be
	//   implemented.

	// Initialize query signaure set (s_q).
	// - s_q is essentially a set containing every XMSS / XMSS^MT signature that is a response from 
	//   the signing oracle in the Query Phase.
	// - Suggested way to implement: An array of length q. The q^th response from the signing oracle
	//   becomes the q^th element in the array.

	// Initialize arbitrary query message (m_q).
	// - This is the message used for each query to the signing oracle. It is ok to use the same 
	//   message every time. 

	// Initialize ISGAttackResult instance that this function will return.
	ISGAttackResult result;

	// *** QUERY PHASE ***

	// Start recording runtime
	// Start recording memory usage

	// Query phase loop. In this loop we query the signing oracle for q distinct signatures of the 
	// query message m_q. Because we may iterate up to, for example, 2^20 times, the iteration 
	// can't be an int. 
	// for ("iterate q times with iteration counter i"):

		// Pause recording runtime. Queries to the signing oracle are NOT counted towards runtime

		// Query signing oracle for XMSS / XMSS^MT signature of query message m_q. In other words, 
		// compute a signature of the message m_q. Call the signature Sig_i.

		// Resume recording runtime.

		// Next, we process each new wots signature in Sig_i.
		// Recall that an XMSS^MT signature contains d wots signatures, with one wots signature 
		// corresponding to each layer of the hyper tree. Dentote the wots signatures in Sig_i as
		// sig_0, ..., sig_d-1. Here, sig_j is on layer j of the hyper tree. Recall that sig_0 is a 
		// signature of the query message m_q. For j != 0, sig_j is a signature of the root of the 
		// Merkle tree that contains sig_j-1.
		// A copy of the wots signature from layer j of the hyper tree is included in 2^{j*h/d} 
		// unique XMSS / XMSS^MT signatures. The wots signature from layer j, sig_j, is new (has not
		// been seen in a previous iteration of the Query Phase loop) if (i % 2^{j*h/d}) = 0.
		// For each new wots signature, we will determine if it contains at least two secret
		// component keys. For each wots signature that does, we will extract a two (random) secret
		// component keys from it, construct a tuple from the secret component keys, and add the 
		// tuple to the SCK Table.
		// *** NOTE *** IGNORE wots signatures with EXACTLY ONE secret component key. In previous
		// versions of the ISG Attack on XMSS, we considered wots signature with one secret
		// component keys, but this is now outdated.

		// First, we test the sig_0, which will always be new since it is on layer 0:
		// - Compute randomized message hash of m_q
		// - Compute base-w representation of randomized message hash and determine which base-w
		//   digits, if any, are 0. When the k^th digit is 0, the k^th component of sig_0 is a 
		//   secret component key.
		// - If there are two or more base-w digits that are 0:
		//   - Randomly select two indices k_0 and k_1 of base-w digits that are 0
		//   - Construct tuple (sig_0[k_0], sig_0[k_1], k_1, i, 0) (feel free to change the form
		//     of this tuple)
		//   - Add (sig_0[k_0], sig_0[k_1], k_1, i, 0) to k_0^th binary search tree in the SCK
		//     Table, keyed by the value of sig_0[k_0].

		// Next, we repeat the previous step with the remaining new wots signature, if there are 
		// any.
		// To determine if sig_j for j!=0 contains two secret component keys, we need to know the 
		// message corresponding to sig_j. This message is the root of the Merkle tree containing
		// sig_j-1. So, each iteration j we compute the root of the Merkle tree containing sig_j-1,
		// then test sig_j to see if it contains a secret component key.
		// Iterate over each remaining new wots signature in Sig_i:
		// for("j=1; i % 2^(j*h/d) = 0 and j < d; increment j) do:
		
			// Compute root of merkle tree containing sig_j-1. This step requires the authorization 
			// path of sig_j-1 (which is included in Sig_i) and the message that sig_j-1 signs.
			// Call the merkle tree root root.

			// Compute base-w representation of root and determine which base-w digits, if any, are 
			// 0. When the k^th digit is 0, the k^th component of sig_j is a secret component key.
			// If there are two or more base-w digits that are 0:
				// Randomly select two indices k_0 and k_1 of base-w digits that are 0
				// Construct tuple (sig_j[k_0], sig_j[k_1], k_1, i, j) (feel free to change the form
				//   of this tuple)
				// Add (sig_j[k_0], sig_j[k_1], k_1, i, j) to k_0^th binary search tree in the SCK
				// Table, keyed by the value of sig_j[k_0].
		// End for loop with iteration counter j

		// Increment iteration counter i
	// End for loop with iteration counter i.

	// *** SECRET-GUESSING PHASE ***

	// Initize first secret OTS key guess, which is an n_reduced bit representation of 0 that is 
	// stored in an n/8 byte array. sotsk_guess is also the itation counter of the Secret-Guessing 
	// Phase. We increment sotsk_guess each iteration as if it were an integer. This ensure we never
	// "make the same guess twice."
	// Feel free to change the implementation of sotsk_guess. 
	char sotsk_guess[(xmss_params->n)/8];
	memset(g, 0, (xmss_params->n)/8);

	// Set result of ISG Attack to failure. If the attack succeeds, it will changed later.
	result.success = 0;

	// Main loop of the Secret-Guessing Phase. Each iteration, generate a set of secret component 
	// keys from a new secret OTS key guess. We search the SCK Table for a tuple keyed by a secret
	// key in this set. If a tuple is found, we forge an XMSS / XMSS^MT signature of the forgery 
	// message m_forgery, then verify the signature. If the signature is valid, the ISG Attack is 
	// complete. Otherwise we continue to iterate. 
	// for("iterate g times with iteration counter sotsk_guess")

		// Using generate a set of secret component keys using sotsk_guess in place of the secret
		// OTS key. Denote the secret component keys sck_0, ... sck_\ell-1.

		// Check if the SCK Table contains a tuple indexed by any of these secret component keys. If
		// a match is found, we attempt to forge a signature.
		// for("k = 0 to \ell-1"):
			// Search the k^th column in the SCK Table for a tuple keyed by sck_k. If such a tuple
			// (sig_j[k], sig_j[k_1], k_1, i, j) where sig_j[k_0] = sck_k is found: 

			// (note, in this case, we always have k_0 = k)

			// Retreive i^th signature from signature query set s_q

			// Use ComputeForgeryFromInternalSecret algorithm to compute forgery of forgery message
			// m_forgery.

			// If the forged XMSS / XMSS^MT signature is valid:
				// Add the forged signature to result. 
				// Set success element of result to true. (In other words, indicate the attack 
				// succeeded)
				result.success = 1;

				// Break Secret-Guessing Phase loop.

		// Increment sotsk_guess as if it were an unsigned integer.
	// End Secret-Guessing Phase loop

	// *** CLEANUP ***

	// Stop recording runtime

	// Stop recording memory usage

	// Calculate total runtime update the runtime element in result
	// result.runtime = 

	// Calculate peak memory usage and update the memory element of result
	// result.memory = 

	return result;
}


// The following functions must be completed in order to use the gdsl binary search tree 
// implementation. If a different binary search tree is being used, delete these functions.

// Notes on the gdsl bstree implementation:
// - To create a new gdsl bstree, use the function:
//     gdsl_bstree_t 	gdsl_bstree_alloc (const char *NAME, gdsl_alloc_func_t ALLOC_F, 
//                                          gdsl_free_func_t FREE_F, gdsl_compare_func_t COMP_F)
// - To create a add an element to the gdsl bstree, use the function:
//     gdsl_element_t 	gdsl_bstree_insert (gdsl_bstree_t T, void *VALUE, int *RESULT)
// - To search for an element in the gdsl bstree, use the function:
//     gdsl_element_t 	gdsl_bstree_search (const gdsl_bstree_t T, gdsl_compare_func_t COMP_F, 
//                                           void *VALUE)
// - See the gdsl bstree documention for further details, including explanation of the arguemtns and
//   return values of these functions.

// Allocation function for adding an SCK Table tuple to a gdsl binary search tree. Dynamically 
// allocated enough memory to store tuple, copies the tuple into that memory, then returns a pointer
// to that memory.
// Params:
//  void * tuple: pointer to tuple
// Return:
//  gdsl_element_t: pointer to copy of tuple
gdsl_element_t sck_table_tuple_alloc(void * tuple){
	// Should look something like:

	// void* ptr = malloc("""size of a tuple""");
	// copy contents of tuple into memory pointed to by ptr
	// return ptr;
}

// Free function for freeing tuple from gdsl bstree. 
// Params: 
//  gdsl_element_t E: pointer to tuple to remove
void sck_table_tuple_free(gdsl_element_t E) {
	// Should look something like:

	// free(E);
}

// Compare function to compare tuples in gdsl bstree. Compares the first secret component key in the
// "first tuple" with the first secret component key in the "second tuple". Ignores the rest of both
// tuples.
// Params:
//  const gdsl_element_t E: pointer to first tuple
//  void* VALUE: pointer to second tuple
// Return:
//  long int: 0 if first secret component keys of both tuples are equal, >0 if E > VALUE, and <0 
//  	if E < VALUE
long int sck_table_tuple_Cmp(const gdsl_element_t E, void* VALUE) {
	
}






