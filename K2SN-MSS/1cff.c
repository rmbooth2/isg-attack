#include <stdio.h>
#include <stdlib.h>
#include <immintrin.h>
#include<malloc.h>
#include<string.h>
#include <inttypes.h>
#include <stdint.h>

#define t 262
#define tb2 131

//typedef unsigned long long int u64;
typedef unsigned __int128 u128;

typedef struct{
	u64	v[5];
}u256;

const u128 b65=(0xffffffffffffffff+1);//0x10000000000000000;
const u64  m64=0xffffffffffffffff;
const u256 zero256 = {0,0,0,0,0};
const u256 one256 = {1,0,0,0,0,};


u256 binoTab[t][tb2+1];

int isgt(u256 a, u256 b);
int iseq(u256 a, u256 b);
int isgteq(u256 a, u256 b);
int isleeq(u256 a, u256 b);
u256 add(u256 a, u256 b);
u256 sub(u256 a, u256 b);
u256 binomial(int a, int b);
void set_binotable();
void convert_u82u256(u8 *ms);
int component_key[tb2];
u256 msg;


void convert_u82u256(u8 *ms){
	msg.v[0]=ms[0];
	msg.v[0]=msg.v[0]|((u64)ms[1]<<8);
	msg.v[0]=msg.v[0]|((u64)ms[2]<<16);
	msg.v[0]=msg.v[0]|((u64)ms[3]<<24);
	msg.v[0]=msg.v[0]|((u64)ms[4]<<32);
	msg.v[0]=msg.v[0]|((u64)ms[5]<<40);
	msg.v[0]=msg.v[0]|((u64)ms[6]<<48);
	msg.v[0]=msg.v[0]|((u64)ms[7]<<56);

	msg.v[1]=ms[8];
	msg.v[1]=msg.v[1]|((u64)ms[9]<<8);
	msg.v[1]=msg.v[1]|((u64)ms[10]<<16);
	msg.v[1]=msg.v[1]|((u64)ms[11]<<24);
	msg.v[1]=msg.v[1]|((u64)ms[12]<<32);
	msg.v[1]=msg.v[1]|((u64)ms[13]<<40);
	msg.v[1]=msg.v[1]|((u64)ms[14]<<48);
	msg.v[1]=msg.v[1]|((u64)ms[15]<<56);

	msg.v[2]=ms[16];
	msg.v[2]=msg.v[2]|((u64)ms[17]<<8);
	msg.v[2]=msg.v[2]|((u64)ms[18]<<16);
	msg.v[2]=msg.v[2]|((u64)ms[19]<<24);
	msg.v[2]=msg.v[2]|((u64)ms[20]<<32);
	msg.v[2]=msg.v[2]|((u64)ms[21]<<40);
	msg.v[2]=msg.v[2]|((u64)ms[22]<<48);
	msg.v[2]=msg.v[2]|((u64)ms[23]<<56);

	msg.v[3]=ms[24];
	msg.v[3]=msg.v[3]|((u64)ms[25]<<8);
	msg.v[3]=msg.v[3]|((u64)ms[26]<<16);
	msg.v[3]=msg.v[3]|((u64)ms[27]<<24);
	msg.v[3]=msg.v[3]|((u64)ms[28]<<32);
	msg.v[3]=msg.v[3]|((u64)ms[29]<<40);
	msg.v[3]=msg.v[3]|((u64)ms[30]<<48);
	msg.v[3]=msg.v[3]|((u64)ms[31]<<56);
	
	msg.v[4]=0;
}

void cff(){
	
	u256 temp;
	u256 m=zero256;
	int q;
	int temp1;

	
	//msg = one256;
	q = 1;
	for(int i=1; i<=tb2; i++){
		while(isgteq(msg,binoTab[t-q][tb2-i])){
			msg = sub(msg,binoTab[t-q][tb2-i]);
			q++;
		}
		component_key[i-1] = q-1;
		q++;
	}

}

int isgt(u256 a, u256 b){
	int i;

	i=4;
	while((a.v[i]==b.v[i]) && (i>0))	i--;

	return (a.v[i]>b.v[i]);
}

int isgteq(u256 a, u256 b){
	int i=4;

	while((a.v[i]==b.v[i]) && (i>=0))	i--;
	
	if(i==-1) return 1;
	else return (a.v[i]>b.v[i]);
}

int isleeq(u256 a, u256 b){
	int i=4;

	while((a.v[i]=b.v[i]) && (i>=0))	i--;
	
	if(i==-1) return 1;
	else return (a.v[i]>b.v[i]);


}
int iseq(u256 a, u256 b){
	return ((a.v[0]==b.v[0])&(a.v[1]==b.v[1])&(a.v[2]==b.v[2])&(a.v[3]==b.v[3])&(a.v[4]==b.v[4]));
}

u256 add(u256 a, u256 b){
	int temp;
	u128 t0,t1,t2,t3,t4,t5,t6,t7;
	u256 c;

	t0 = (u128)a.v[0]+b.v[0];
	t1 = (u128)a.v[1]+b.v[1];
	t2 = (u128)a.v[2]+b.v[2];
	t3 = (u128)a.v[3]+b.v[3];
	t4 = (u128)a.v[4]+b.v[4];
	
	temp = t0 > m64; c.v[0] = t0 & m64; t1 = t1 + temp;
	temp = t1 > m64; c.v[1] = t1 & m64; t2 = t2 + temp;
	temp = t2 > m64; c.v[2] = t2 & m64; t3 = t3 + temp;
	temp = t3 > m64; c.v[3] = t3 & m64; t4 = t4 + temp;
	c.v[4] = t4;

	return c;
}

u256 sub(u256 a, u256 b){
	u256 c;

	if (a.v[0]>=b.v[0]){ 
		c.v[0]=a.v[0]-b.v[0];
	}else{ 	c.v[0] = m64 - b.v[0]; c.v[0] = c.v[0] + a.v[0] + 1;
		b.v[1] += 1;
	}

	if (a.v[1]>=b.v[1]){ 
		c.v[1]=a.v[1]-b.v[1];
	}else{ 	c.v[1] = m64 - b.v[1]; c.v[1] = c.v[1] + a.v[1] + 1;
		b.v[2] += 1;
	}

	if (a.v[2]>=b.v[2]){ 
		c.v[2]=a.v[2]-b.v[2];
	}else{ 	c.v[2] = m64 - b.v[2]; c.v[2] = c.v[2] + a.v[2] + 1;
		b.v[3] += 1;
	}

	if (a.v[3]>=b.v[3]){ 
		c.v[3]=a.v[3]-b.v[3];
	}else{ 	c.v[3] = m64 - b.v[3]; c.v[3] = c.v[3] + a.v[3] + 1;
		b.v[4] += 1;
	}

	c.v[4]=a.v[4]-b.v[4];

	return c;
}



u256 subone(u256 a){
	u256 c;

	int i=0;

	while(a.v[i]==0) i++;
	c.v[i] = a.v[i]-1;
	
	for(int j=i-1;j>=0;j--)	c.v[i]=m64;
	for(int j=i+1;j<5;j++)	c.v[i]=a.v[i];
	
	return c;
}


void set_binotable(){
	int n, m;
	u256 a=zero256;

	for(n=0; n<t; n++)	binoTab[n][0]=one256;
	for(n=0; n<=tb2; n++)	binoTab[n][n]=one256;
	for(n=1; n<=tb2; n++){
		for(m=1; m<n; m++)	binoTab[n][m]=add(binoTab[n-1][m-1],binoTab[n-1][m]);
	}
	for(n=tb2+1; n<t; n++){
		for(m=1; m<=tb2; m++)	binoTab[n][m]=add(binoTab[n-1][m-1],binoTab[n-1][m]);
	}

}

