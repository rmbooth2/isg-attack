#include "swifft-avx2-16.h"
#define vecMult16Reduce1(I0, I1, O) { \
	vec T0, T1; \
	vec A0, A1; \
	vec OT; \
	T0 = _mm256_mulhi_epu16(I0, I1); \
	T1 = _mm256_mullo_epi16(I0, I1); \
	OT = _mm256_add_epi16(T0, T1); \
	A0 = _mm256_and_si256(OT,mask255); A1 = _mm256_srli_epi16(OT,8); O = _mm256_sub_epi16(A0,A1); \
}

//#define vecMult16Reduce3(I0, I1, O) { \
	vec T0, T1; \
	vec A0, A1; \
	vec OT; \
	T0 = _mm256_mulhi_epi16(I0, I1); \
	T1 = _mm256_mullo_epi16(I0, I1); \
	A0 = _mm256_and_si256(T1,mask255); A1 = _mm256_srli_epi16(T1,8); T1 = _mm256_sub_epi16(A0,A1); \
	T1 = _mm256_add_epi16(T1,p257); \
	OT = _mm256_add_epi16(T0, T1); \
	A0 = _mm256_and_si256(OT,mask255); A1 = _mm256_srli_epi16(OT,8); O = _mm256_sub_epi16(A0,A1); \
}


//#define vecMult16Reduce1(I0, I1, O) { \
	vec T0, T1; \
	vec A0, A1, A2, A3, A4; \
	vec OT; \
	OT = _mm256_mullo_epi16(I0, I1); \
	A0 = _mm256_and_si256(OT,mask255); A1 = _mm256_srli_epi16(OT,8); O = _mm256_sub_epi16(A0,A1); \
}

#define vecMult16Reduce2(I0, I1, O) { \
	vec T0, T1; \
	vec A0, A1, A2, A3, A4; \
	vec OT1, OT2; \
	T0 = _mm256_mulhi_epu16(I0, I1); \
	T1 = _mm256_mullo_epi16(I0, I1); \
	A0 = _mm256_and_si256(T1,mask255); A1 = _mm256_srli_epi16(T1,8); OT2 = _mm256_sub_epi16(A0,A1); \
	OT1 = _mm256_add_epi16(OT2,T0); \
	A2 = _mm256_cmpgt_epi16(OT1,allone); A3 = _mm256_xor_si256(A2,allone); A4 = _mm256_and_si256(A3,p257); \
	O = _mm256_add_epi16(OT1,A4); \
}

#define vecMult16Reduce3(I0, I1, O) { \
	vec T0, T1; \
	vec A0, A1; \
	vec OT; \
	T0 = _mm256_mulhi_epu16(I0, I1); \
	T1 = _mm256_mullo_epi16(I0, I1); \
	A0 = _mm256_and_si256(T1,mask255); A1 = _mm256_srli_epi16(T1,8); T1 = _mm256_sub_epi16(A0,A1); \
	T1 = _mm256_add_epi16(T0, T1); \
	A0 = _mm256_cmpgt_epi16(T1,allone); A0 = _mm256_xor_si256(A0,allone); A0 = _mm256_and_si256(A0,p257);\
	O = _mm256_add_epi16(A0,T1); \
}

extern void bntt16(int xbyte[16][4], vec Y[16][4]);
inline void bntt16(int xbyte[16][4], vec Y[16][4]){
	for(int row=0;row<16;row++){	
		vecMult16Reduce3(M_K0_I0[0], T_K0_I0[xbyte[row][0]], Y_temp1[0]); 
		vecMult16Reduce3(M_K0_I0[1], T_K0_I0[xbyte[row][1]], Y_temp1[1]);
		vecMult16Reduce3(M_K0_I0[2], T_K0_I0[xbyte[row][2]], Y_temp1[2]);
		vecMult16Reduce3(M_K0_I0[3], T_K0_I0[xbyte[row][3]], Y_temp1[3]);

		Y_temp2[0] = _mm256_add_epi16(Y_temp1[0],Y_temp1[2]);
		Y_temp2[1] = _mm256_add_epi16(Y_temp1[1],Y_temp1[3]);
		Y[row][0] = _mm256_add_epi16(Y_temp2[0],Y_temp2[1]); 
		
		Y_temp2[2] = _mm256_add_epi16(Y_temp2[0],p257_2);
		Y[row][2] = _mm256_sub_epi16(Y_temp2[2],Y_temp2[1]); 
				
		
		Y_temp2[0] = _mm256_add_epi16(Y_temp1[0],p257_2);
		Y_temp2[1] = _mm256_sub_epi16(Y_temp2[0],Y_temp1[2]);

		Y_temp2[2] = _mm256_add_epi16(Y_temp1[1],p257_2);
		Y_temp2[3] = _mm256_sub_epi16(Y_temp2[2],Y_temp1[3]);
		Y_temp2[4] = _mm256_slli_epi16(Y_temp2[3],4);
		Y[row][1] = _mm256_add_epi16(Y_temp2[1],Y_temp2[4]); ReduceY2(&Y[row][1]);
		
		Y_temp2[1] = _mm256_add_epi16(Y_temp2[1],p257_7);
		Y[row][3] = _mm256_sub_epi16(Y_temp2[1],Y_temp2[4]); ReduceY2(&Y[row][3]);
	}
}
extern void gntt16(vec key[16][4], vec A[16][4]);
inline void gntt16(vec key[16][4], vec A[16][4]){
	vec t1,t2,t3,t4;
	vec temp[4];
	for(int row=0;row<16;row++){
		for(int k0=0; k0<4; k0++){
			temp[k0] = zero;
			for(int k1=0; k1<8; k1++){
				t1 = _mm256_permutevar8x32_epi32(key[row][k0], permute[k1]);
				t2 = _mm256_and_si256(t1,selec[1]);
				t1 = _mm256_and_si256(t1,selec[0]);
				t3 = _mm256_slli_epi32(t1,16);
				t4 = _mm256_srli_epi32(t2,16);
				t1 = _mm256_or_si256(t1,t3);
				t2 = _mm256_or_si256(t2,t4);

				vecMult16Reduce3(t1, k0i0[2*k1], t3);
				vecMult16Reduce3(t2, k0i0[2*k1+1], t4);
				temp[k0]  = _mm256_add_epi16(temp[k0],t3);
				temp[k0]  = _mm256_add_epi16(temp[k0],t4); 	ReduceY2(&temp[k0]);
			}
		}

		vecMult16Reduce3(M_K0_I0[0], temp[0], Y_temp1[0]);
		vecMult16Reduce3(M_K0_I0[1], temp[1], Y_temp1[1]);
		vecMult16Reduce3(M_K0_I0[2], temp[2], Y_temp1[2]);
		vecMult16Reduce3(M_K0_I0[3], temp[3], Y_temp1[3]);

		Y_temp2[0] = _mm256_add_epi16(Y_temp1[0],Y_temp1[2]);
		Y_temp2[1] = _mm256_add_epi16(Y_temp1[1],Y_temp1[3]);
		A[row][0] = _mm256_add_epi16(Y_temp2[0],Y_temp2[1]);
		
		Y_temp2[2] = _mm256_add_epi16(Y_temp2[0],p257_2);
		A[row][2] = _mm256_sub_epi16(Y_temp2[2],Y_temp2[1]);
				
		
		Y_temp2[0] = _mm256_add_epi16(Y_temp1[0],p257_2);
		Y_temp2[1] = _mm256_sub_epi16(Y_temp2[0],Y_temp1[2]);

		Y_temp2[2] = _mm256_add_epi16(Y_temp1[1],p257_2);
		Y_temp2[3] = _mm256_sub_epi16(Y_temp2[2],Y_temp1[3]);
		Y_temp2[4] = _mm256_slli_epi16(Y_temp2[3],4);
		A[row][1] = _mm256_add_epi16(Y_temp2[1],Y_temp2[4]);	ReduceY2(&A[row][1]);
		
		Y_temp2[1] = _mm256_add_epi16(Y_temp2[1],p257_7);
		A[row][3] = _mm256_sub_epi16(Y_temp2[1],Y_temp2[4]);	ReduceY2(&A[row][3]);

	}	

}

