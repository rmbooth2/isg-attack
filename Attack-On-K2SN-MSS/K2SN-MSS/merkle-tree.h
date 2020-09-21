#ifndef MERKLE_TREE_H_
#define MERKLE_TREE_H_

#include <immintrin.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdint.h>

#define sklen 128
#define pklen 72
#define rglen 64
#define ranlen 128
#define usr 4096//2^h
//TODO right now h = log(1024) + 1, and is not odd, so...
#define h 12 //must be even
#define l 9
#define merlen (2*pklen-sklen)

typedef unsigned char uint8;
typedef unsigned long int uint32;

typedef unsigned char uint8;
extern int key_length;

typedef struct node{
	uint8 key[pklen];
}node;

typedef struct mssnode{
	uint8 key[pklen];
	uint32 height;
	uint32 indx;
}mssnode;

typedef struct sk_node{
	uint8 key[sklen];
}sk_node;


typedef struct treehash{
	node	v;
	mssnode treestack[h-1];
	uint32	finalized;
	uint32 	startleaf;
	uint32	lowheight;
	int 	top;
	
}treehash;

treehash instance[h-2];


#endif
