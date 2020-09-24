#include <stdio.h>
#include <time.h>
#include <gdsl.h>
#include <string.h>

// Set of parameters defining an XMSS or XMSS^MT scheme and number of bits to chop secret OTS seeds 
// to.
// Feel free to modify, add or remove elements, or to remove or replace this struct altogether
typedef struct XMSSModifiedParameterSets {
    // Security parameter n
    unsigned int n; 

    // Winternitz parameter w
    unsigned int w;

    // Length of hash chain, usually denoted $\ell$ or len
    unsigned int len;

    // Height of hyper tree h
    unsigned int h;

    // Number of layers in hyper tree d
    unsigned int d;

    // Secret OTS seeds should be chopped n_reduced bits
    unsigned int n_reduced;
} XMSSModifiedParameterSet;


// Results of an interation of the ISG Attack
// Feel free to modify, add or remove elements, or to remove or replace this struct altogether
typedef struct ISGAttackResults {
    // Runtime of attack in clock cycles
    unsigned int runtime;

    // Indicates whether attack succeeded or failed
    int success;

    // Peak memory used by attack in bytes
    unsigned int memory;

    // Forged signature
    // unsure of datatype

} ISGAttackResult;


// Secret component key table. Essentially an array of length \ell of binary search trees. The i^th
// tree contains an ordered set of tuples. The first element of the tuple is the i^th secret 
// component key of a wots instance. The next element is another secret component key of the same
// wots instance. The remaining elements contain enough information to determine: 1. the location of
// the wots instance in the hyper tree, and 2. the index of the other secret component key. The 
// tuple is keyed by the value of the i^th secret component key.
// Feel free to modify, add or remove elements, or to remove or replace this struct altogether
typedef struct SCKTables {

} SCKTable;

// A tuple in the secret component key table. The first element of the tuple is the i^th secret 
// component key of a wots instance. The next element is another secret component key of the same
// wots instance. The remaining elements contain enough information to determine: 1. the location of
// the wots instance in the hyper tree, and 2. the index of the other secret component key. The 
// tuple is keyed by the value of the i^th secret component key.
// Feel free to modify, add or remove elements, or to remove or replace this struct altogether
typedef struct SCKTuples {
    //First secret component key

    //Second secret component key

    //Indices

} SCKTuple;

ISGAttackResult isg_attack_xmss(unsigned int q, unsigned int g, unsigned char* m_forgery, 
    XMSSModifiedParameterSet* xmss_params);

gdsl_element_t sck_table_tuple_alloc(void * tuple);

void sck_table_tuple_free(gdsl_element_t E);

long int sck_table_tuple_cmp(const gdsl_element_t E, void* VALUE);