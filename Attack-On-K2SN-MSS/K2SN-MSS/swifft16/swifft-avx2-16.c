#include "ntt16.h"
//#include "../ChaCha20/chacha.c"

extern void parse(int xbyte[16][4], u8 x[sklen]);
inline void parse(int xbyte[16][4], u8 x[sklen]){
	int i,j,k,row_t;

	/*for(int row=0;row<16;row++){
		printf("\n");
		for(i=0; i<8; i++){
			printf("%hhu ",x[row*8+i]);
		}
		printf("\n");
	}
	*/
	for(int row=0;row<16;row++){
		row_t = row*8;
		for(i=0; i<4; i++){
			xbyte[row][i] = x[row_t+2*i+1];
			xbyte[row][i] = (xbyte[row][i]<<8)|x[row_t+2*i];
		}
	}

}

void ReduceY1(vec *Y){
	vec a0,a1;

	a0 = _mm256_and_si256(*Y,mask255); a1 = _mm256_srli_epi16(*Y,8); *Y = _mm256_sub_epi16(a0,a1);
}

void ReduceY2(vec *Y){
	vec a0,a1;

	a0 = _mm256_and_si256(*Y,mask255); a1 = _mm256_srli_epi16(*Y,8); *Y = _mm256_sub_epi16(a0,a1);
	a0 = _mm256_cmpgt_epi16(*Y,allone);//print(*Y);
	a0 = _mm256_xor_si256(a0,allone); a0 = _mm256_and_si256(a0,p257);
	*Y = _mm256_add_epi16(*Y,a0);//print(*Y);
	
}

//T0 = _mm256_and_si256(I0, I1); T1 = _mm256_and_si256(T0, p256);	T2 = _mm256_srli_epi16(T1,8); \

void print_vec(vec Y){

	int i,j;
	uu16 opi[16];
	printf("\n");
  	opi[0]  = 0[(uu16 *) &Y];printf(" %hu ",opi[0]%257);
	opi[1]  = 1[(uu16 *) &Y];printf(" %hu ",opi[1]%257);
	opi[2]  = 2[(uu16 *) &Y];printf(" %hu ",opi[2]%257);
	opi[3]  = 3[(uu16 *) &Y];printf(" %hu ",opi[3]%257);
	opi[4]  = 4[(uu16 *) &Y];printf(" %hu ",opi[4]%257);
	opi[5]  = 5[(uu16 *) &Y];printf(" %hu ",opi[5]%257);
	opi[6]  = 6[(uu16 *) &Y];printf(" %hu ",opi[6]%257);
	opi[7]  = 7[(uu16 *) &Y];printf(" %hu ",opi[7]%257);
	opi[8]  = 8[(uu16 *) &Y];printf(" %hu ",opi[8]%257);
	opi[9]  = 9[(uu16 *) &Y];printf(" %hu ",opi[9]%257);
	opi[10] = 10[(uu16 *) &Y];printf(" %hu ",opi[10]%257);
	opi[11] = 11[(uu16 *) &Y];printf(" %hu ",opi[11]%257);
	opi[12] = 12[(uu16 *) &Y];printf(" %hu ",opi[12]%257);
	opi[13] = 13[(uu16 *) &Y];printf(" %hu ",opi[13]%257);
	opi[14] = 14[(uu16 *) &Y];printf(" %hu ",opi[14]%257);
	opi[15] = 15[(uu16 *) &Y];printf(" %hu ",opi[15]%257);
	printf("\n");
}

void print(vec Y){

	int i,j;
	uu16 opi[16];
	printf("\n");
  	opi[0]  = 0[(uu16 *) &Y];printf(" %hu ",opi[0]);
	opi[1]  = 1[(uu16 *) &Y];printf(" %hu ",opi[1]);
	opi[2]  = 2[(uu16 *) &Y];printf(" %hu ",opi[2]);
	opi[3]  = 3[(uu16 *) &Y];printf(" %hu ",opi[3]);
	opi[4]  = 4[(uu16 *) &Y];printf(" %hu ",opi[4]);
	opi[5]  = 5[(uu16 *) &Y];printf(" %hu ",opi[5]);
	opi[6]  = 6[(uu16 *) &Y];printf(" %hu ",opi[6]);
	opi[7]  = 7[(uu16 *) &Y];printf(" %hu ",opi[7]);
	opi[8]  = 8[(uu16 *) &Y];printf(" %hu ",opi[8]);
	opi[9]  = 9[(uu16 *) &Y];printf(" %hu ",opi[9]);
	opi[10] = 10[(uu16 *) &Y];printf(" %hu ",opi[10]);
	opi[11] = 11[(uu16 *) &Y];printf(" %hu ",opi[11]);
	opi[12] = 12[(uu16 *) &Y];printf(" %hu ",opi[12]);
	opi[13] = 13[(uu16 *) &Y];printf(" %hu ",opi[13]);
	opi[14] = 14[(uu16 *) &Y];printf(" %hu ",opi[14]);
	opi[15] = 15[(uu16 *) &Y];printf(" %hu ",opi[15]);
	printf("\n");
}


extern void SWIFFT(int xbyte[16][4],vec A[16][4], u8 *hop);
inline void SWIFFT(int xbyte[16][4],vec A[16][4], u8 *hop){
	int i1;
	int k0;
	vec Yt[8];
	int t;
	vec op_temp[8];
	vec mk0i0, poi1k0;
		
	bntt16(xbyte,Y);
	//print(Y[0][3]);
	//for(int i=0;i<16;i++) {print(Y[i][0]);print(Y[i][1]);print(Y[i][2]);print(Y[i][3]);}
	for(int i=0; i<4; i++){
		vecMult16Reduce3(Y[0][i],  A[0][i],  Y_temp1[0]);
		vecMult16Reduce3(Y[1][i],  A[1][i],  Y_temp1[1]);
		vecMult16Reduce3(Y[2][i],  A[2][i],  Y_temp1[2]);
		vecMult16Reduce3(Y[3][i],  A[3][i],  Y_temp1[3]);
		vecMult16Reduce3(Y[4][i],  A[4][i],  Y_temp1[4]);
		vecMult16Reduce3(Y[5][i],  A[5][i],  Y_temp1[5]);
		vecMult16Reduce3(Y[6][i],  A[6][i],  Y_temp1[6]);
		vecMult16Reduce3(Y[7][i],  A[7][i],  Y_temp1[7]);
		vecMult16Reduce3(Y[8][i],  A[8][i],  Y_temp1[8]);
		vecMult16Reduce3(Y[9][i],  A[9][i],  Y_temp1[9]);
		vecMult16Reduce3(Y[10][i], A[10][i], Y_temp1[10]);
		vecMult16Reduce3(Y[11][i], A[11][i], Y_temp1[11]);
		vecMult16Reduce3(Y[12][i], A[12][i], Y_temp1[12]);
		vecMult16Reduce3(Y[13][i], A[13][i], Y_temp1[13]);
		vecMult16Reduce3(Y[14][i], A[14][i], Y_temp1[14]);
		vecMult16Reduce3(Y[15][i], A[15][i], Y_temp1[15]);

		op_temp[0] = _mm256_add_epi16(Y_temp1[0],Y_temp1[1]);   op_temp[1] = _mm256_add_epi16(Y_temp1[2],Y_temp1[3]); 
		op_temp[2] = _mm256_add_epi16(Y_temp1[4],Y_temp1[5]);   op_temp[3] = _mm256_add_epi16(Y_temp1[6],Y_temp1[7]);
		op_temp[4] = _mm256_add_epi16(Y_temp1[8],Y_temp1[9]);   op_temp[5] = _mm256_add_epi16(Y_temp1[10],Y_temp1[11]); 
		op_temp[6] = _mm256_add_epi16(Y_temp1[12],Y_temp1[13]); op_temp[7] = _mm256_add_epi16(Y_temp1[14],Y_temp1[15]);

		op_temp[0] = _mm256_add_epi16(op_temp[0],op_temp[1]); op_temp[2] = _mm256_add_epi16(op_temp[2],op_temp[3]); 
		op_temp[4] = _mm256_add_epi16(op_temp[4],op_temp[5]); op_temp[6] = _mm256_add_epi16(op_temp[6],op_temp[7]);

		op_temp[0] = _mm256_add_epi16(op_temp[0],op_temp[2]); op_temp[4] = _mm256_add_epi16(op_temp[4],op_temp[6]); 

		op[i] = _mm256_add_epi16(op_temp[0],op_temp[4]);	ReduceY2(&op[i]);ReduceY2(&op[i]);
		
	}
	
	//print(op[0]);print(op[1]);print(op[2]);print(op[3]);
	unpackY(op,hop);

}

int gSWIFFT(int x[16][64], vec A[16][4], u32 *pk){
	int i1;
	int k0;
	vec Yt[8];
	int t;
	vec op_temp[8];
	vec mk0i0, poi1k0;
	vec X[16][4],Y[16][4];

	for(int row=0;row<16;row++){
		for(k0=0; k0 < 4; k0++){
			0[(uu16 *) &(X[row][k0])]  = x[row][16*k0+0];
			1[(uu16 *) &(X[row][k0])]  = x[row][16*k0+1];
			2[(uu16 *) &(X[row][k0])]  = x[row][16*k0+2];
			3[(uu16 *) &(X[row][k0])]  = x[row][16*k0+3];
			4[(uu16 *) &(X[row][k0])]  = x[row][16*k0+4];
			5[(uu16 *) &(X[row][k0])]  = x[row][16*k0+5];
			6[(uu16 *) &(X[row][k0])]  = x[row][16*k0+6];
			7[(uu16 *) &(X[row][k0])]  = x[row][16*k0+7];
			8[(uu16 *) &(X[row][k0])]  = x[row][16*k0+8];
			9[(uu16 *) &(X[row][k0])]  = x[row][16*k0+9];
			10[(uu16 *) &(X[row][k0])] = x[row][16*k0+10];
			11[(uu16 *) &(X[row][k0])] = x[row][16*k0+11];
			12[(uu16 *) &(X[row][k0])] = x[row][16*k0+12];
			13[(uu16 *) &(X[row][k0])] = x[row][16*k0+13];
			14[(uu16 *) &(X[row][k0])] = x[row][16*k0+14];
			15[(uu16 *) &(X[row][k0])] = x[row][16*k0+15];
		}
	}

	gntt16(X,Y);
	//for(int i=0;i<16;i++) {print(Y[i][0]);print(Y[i][1]);print(Y[i][2]);print(Y[i][3]);}
	for(int i=0; i<4; i++){
		vecMult16Reduce3(Y[0][i],  A[0][i],  Y_temp1[0]);//ReduceY2(&Y_temp1[0]);
		vecMult16Reduce3(Y[1][i],  A[1][i],  Y_temp1[1]);//ReduceY2(&Y_temp1[1]);
		vecMult16Reduce3(Y[2][i],  A[2][i],  Y_temp1[2]);//ReduceY2(&Y_temp1[2]);
		vecMult16Reduce3(Y[3][i],  A[3][i],  Y_temp1[3]);//ReduceY2(&Y_temp1[3]);
		vecMult16Reduce3(Y[4][i],  A[4][i],  Y_temp1[4]);//ReduceY2(&Y_temp1[4]);
		vecMult16Reduce3(Y[5][i],  A[5][i],  Y_temp1[5]);//ReduceY2(&Y_temp1[5]);
		vecMult16Reduce3(Y[6][i],  A[6][i],  Y_temp1[6]);//ReduceY2(&Y_temp1[6]);
		vecMult16Reduce3(Y[7][i],  A[7][i],  Y_temp1[7]);//ReduceY2(&Y_temp1[7]);
		vecMult16Reduce3(Y[8][i],  A[8][i],  Y_temp1[8]);//ReduceY2(&Y_temp1[8]);
		vecMult16Reduce3(Y[9][i],  A[9][i],  Y_temp1[9]);//ReduceY2(&Y_temp1[9]);
		vecMult16Reduce3(Y[10][i], A[10][i], Y_temp1[10]);//ReduceY2(&Y_temp1[10]);
		vecMult16Reduce3(Y[11][i], A[11][i], Y_temp1[11]);//ReduceY2(&Y_temp1[11]);
		vecMult16Reduce3(Y[12][i], A[12][i], Y_temp1[12]);//ReduceY2(&Y_temp1[12]);
		vecMult16Reduce3(Y[13][i], A[13][i], Y_temp1[13]);//ReduceY2(&Y_temp1[13]);
		vecMult16Reduce3(Y[14][i], A[14][i], Y_temp1[14]);//ReduceY2(&Y_temp1[14]);
		vecMult16Reduce3(Y[15][i], A[15][i], Y_temp1[15]);//ReduceY2(&Y_temp1[15]);

		op_temp[0] = _mm256_add_epi16(Y_temp1[0],Y_temp1[1]);  //ReduceY2(&op_temp[0]); 
		op_temp[1] = _mm256_add_epi16(Y_temp1[2],Y_temp1[3]);  //ReduceY2(&op_temp[1]); 
		op_temp[2] = _mm256_add_epi16(Y_temp1[4],Y_temp1[5]);  //ReduceY2(&op_temp[2]); 
		op_temp[3] = _mm256_add_epi16(Y_temp1[6],Y_temp1[7]);  //ReduceY2(&op_temp[3]); 
		op_temp[4] = _mm256_add_epi16(Y_temp1[8],Y_temp1[9]);  //ReduceY2(&op_temp[4]); 
		op_temp[5] = _mm256_add_epi16(Y_temp1[10],Y_temp1[11]);//ReduceY2(&op_temp[5]); 
		op_temp[6] = _mm256_add_epi16(Y_temp1[12],Y_temp1[13]);//ReduceY2(&op_temp[6]); 
		op_temp[7] = _mm256_add_epi16(Y_temp1[14],Y_temp1[15]);//ReduceY2(&op_temp[7]); 

		op_temp[0] = _mm256_add_epi16(op_temp[0],op_temp[1]); //ReduceY2(&op_temp[0]); 
		op_temp[2] = _mm256_add_epi16(op_temp[2],op_temp[3]); //ReduceY2(&op_temp[2]); 
		op_temp[4] = _mm256_add_epi16(op_temp[4],op_temp[5]); //ReduceY2(&op_temp[4]); 
		op_temp[6] = _mm256_add_epi16(op_temp[6],op_temp[7]); //ReduceY2(&op_temp[6]); 

		op_temp[0] = _mm256_add_epi16(op_temp[0],op_temp[2]); //ReduceY2(&op_temp[2]); 
		op_temp[4] = _mm256_add_epi16(op_temp[4],op_temp[6]); //ReduceY2(&op_temp[6]); 

		op[i] = _mm256_add_epi16(op_temp[0],op_temp[4]); ReduceY2(&op[i]);ReduceY2(&op[i]);
		
	}
	
	//print(op[0]);print(op[1]);print(op[2]);print(op[3]);
	unpack_rgY(op,pk);

}

/*void inline read_Input(){
	int i,j;
	for(i=0;i<16;i++){
		for(j=0;j<8;j++){
			scanf("%d",&(x[i][j]));
		}
	}
	for(i=0;i<16;i++){
		for(j=0;j<64;j++){
			scanf("%d",&(a[i][j]));
		}
	}
}
*/
void set_Key(u32 indx, u32 height){
	int y[16][64];
	int i,k,j;
	int t1,t2;
	int t;
	int om_odd_pow[64];
	vec om_base[8], om_temp[8][8], key[16][4],temp[4];
	vec tk0i0k[8];
	ECRYPT_ctx seed_ctx;

	u8 ina[1024]={0};

	//for(i=0;i<32;i++){
	//	for(j=0;j<32;j++){
	//		printf("%hhu,",ina[i*32+j]);
	//	}
	//	printf("\n");
	//}

	ina[0] = indx & 255; indx = indx >>8;
	ina[1] = indx & 255; indx = indx >>8;
	ina[2] = indx & 255; indx = indx >>8;
	ina[3] = indx & 255;

	ina[512] = height;

	ECRYPT_keysetup(&seed_ctx,hk_seed,256,64);
	ECRYPT_ivsetup(&seed_ctx,hk_iv);
	ECRYPT_encrypt_bytes(&seed_ctx,ina,a,1024);
	
	vec Y_temp1[4],Y_temp2[8],Y_temp3[8];


	for(int row=0;row<16;row++){
		t1 = 64*row;
		for(int k0=0; k0 < 4; k0++){
			t2 = t1 + 16*k0;
			0[(u16 *) &(A[row][k0])]  = a[t2+0];
			1[(u16 *) &(A[row][k0])]  = a[t2+1];
			2[(u16 *) &(A[row][k0])]  = a[t2+2];
			3[(u16 *) &(A[row][k0])]  = a[t2+3];
			4[(u16 *) &(A[row][k0])]  = a[t2+4];
			5[(u16 *) &(A[row][k0])]  = a[t2+5];
			6[(u16 *) &(A[row][k0])]  = a[t2+6];
			7[(u16 *) &(A[row][k0])]  = a[t2+7];
			8[(u16 *) &(A[row][k0])]  = a[t2+8];
			9[(u16 *) &(A[row][k0])]  = a[t2+9];
			10[(u16 *) &(A[row][k0])] = a[t2+10];
			11[(u16 *) &(A[row][k0])] = a[t2+11];
			12[(u16 *) &(A[row][k0])] = a[t2+12];
			13[(u16 *) &(A[row][k0])] = a[t2+13];
			14[(u16 *) &(A[row][k0])] = a[t2+14];
			15[(u16 *) &(A[row][k0])] = a[t2+15];
		}
	}
	
	
}
void unpack_rgY(vec Y[4],u32 *pk){
	int i,j;
	//u32 opi[4][16];
	for(i=0;i<4;i++){
	    	pk[16*i+0]  = 0[(uu16 *) &Y[i]]%257;
	   	pk[16*i+1]  = 1[(uu16 *) &Y[i]]%257;
	    	pk[16*i+2]  = 2[(uu16 *) &Y[i]]%257;
	    	pk[16*i+3]  = 3[(uu16 *) &Y[i]]%257;
	    	pk[16*i+4]  = 4[(uu16 *) &Y[i]]%257;
	   	pk[16*i+5]  = 5[(uu16 *) &Y[i]]%257;
	    	pk[16*i+6]  = 6[(uu16 *) &Y[i]]%257;
	    	pk[16*i+7]  = 7[(uu16 *) &Y[i]]%257;
	    	pk[16*i+8]  = 8[(uu16 *) &Y[i]]%257;
	   	pk[16*i+9]  = 9[(uu16 *) &Y[i]]%257;
	    	pk[16*i+10] = 10[(uu16 *) &Y[i]]%257;
	    	pk[16*i+11] = 11[(uu16 *) &Y[i]]%257;
	    	pk[16*i+12] = 12[(uu16 *) &Y[i]]%257;
	   	pk[16*i+13] = 13[(uu16 *) &Y[i]]%257;
	    	pk[16*i+14] = 14[(uu16 *) &Y[i]]%257;
	    	pk[16*i+15] = 15[(uu16 *) &Y[i]]%257;


	}
	
	
}


void unpackY(vec Y[4],u8 *pk){
	int i,j;
	u32 opi[4][16];
	for(i=0;i<4;i++){
	    	opi[i][0]  = 0[(uu16 *) &Y[i]]%257;
	   	opi[i][1]  = 1[(uu16 *) &Y[i]]%257;
	    	opi[i][2]  = 2[(uu16 *) &Y[i]]%257;
	    	opi[i][3]  = 3[(uu16 *) &Y[i]]%257;
	    	opi[i][4]  = 4[(uu16 *) &Y[i]]%257;
	   	opi[i][5]  = 5[(uu16 *) &Y[i]]%257;
	    	opi[i][6]  = 6[(uu16 *) &Y[i]]%257;
	    	opi[i][7]  = 7[(uu16 *) &Y[i]]%257;
	    	opi[i][8]  = 8[(uu16 *) &Y[i]]%257;
	   	opi[i][9]  = 9[(uu16 *) &Y[i]]%257;
	    	opi[i][10] = 10[(uu16 *) &Y[i]]%257;
	    	opi[i][11] = 11[(uu16 *) &Y[i]]%257;
	    	opi[i][12] = 12[(uu16 *) &Y[i]]%257;
	   	opi[i][13] = 13[(uu16 *) &Y[i]]%257;
	    	opi[i][14] = 14[(uu16 *) &Y[i]]%257;
	    	opi[i][15] = 15[(uu16 *) &Y[i]]%257;

		
		/*pk[i*18+0] = (u8)(0xFF & (0[(uu16 *) &Y[i]]));

		pk[i*18+1] = (u8)(0x1 & ((0[(uu16 *) &Y[i]])>>8));
		pk[i*18+1] = pk[i*18+1] | (u8)((0x7F&(1[(uu16 *) &Y[i]]))<<1);

		pk[i*18+2] = (u8)(0x3 & ((1[(uu16 *) &Y[i]])>>7));
		pk[i*18+2] = pk[i*18+2] | (u8)((0x3F&(2[(uu16 *) &Y[i]]))<<2);

		pk[i*18+3] = (u8)(0x7 & ((2[(uu16 *) &Y[i]])>>6));
		pk[i*18+3] = pk[i*18+3] | (u8)((0x1F&(3[(uu16 *) &Y[i]]))<<3);

		pk[i*18+4] = (u8)(0xF & ((3[(uu16 *) &Y[i]])>>5));
		pk[i*18+4] = pk[i*18+4] | (u8)((0xF&(4[(uu16 *) &Y[i]]))<<4);

		pk[i*18+5] = (u8)(0x1F & ((4[(uu16 *) &Y[i]])>>4));
		pk[i*18+5] = pk[i*18+5] | (u8)((0x7&(5[(uu16 *) &Y[i]]))<<5);

		pk[i*18+6] = (u8)(0x3F & ((5[(uu16 *) &Y[i]])>>3));
		pk[i*18+6] = pk[i*18+6] | (u8)((0x3&(6[(uu16 *) &Y[i]]))<<6);

		pk[i*18+7] = (u8)(0x7F & ((6[(uu16 *) &Y[i]])>>2));
		pk[i*18+7] = pk[i*18+7] | (u8)((0x1&(7[(uu16 *) &Y[i]]))<<7);

		pk[i*18+8] = (u8)(0xFF & ((7[(uu16 *) &Y[i]])>>1));
		
		pk[i*18+9] = (u8)(0xFF & (8[(uu16 *) &Y[i]]));

		pk[i*18+10] = (u8)(0x1 & ((8[(uu16 *) &Y[i]])>>8));
		pk[i*18+10] = pk[i*18+10] | (u8)((0x7F&(9[(uu16 *) &Y[i]]))<<1);

		pk[i*18+11] = (u8)(0x3 & ((9[(uu16 *) &Y[i]])>>7));
		pk[i*18+11] = pk[i*18+11] | (u8)((0x3F&(10[(uu16 *) &Y[i]]))<<2);

		pk[i*18+12] = (u8)(0x7 & ((10[(uu16 *) &Y[i]])>>6));
		pk[i*18+12] = pk[i*18+12] | (u8)((0x1F&(11[(uu16 *) &Y[i]]))<<3);

		pk[i*18+13] = (u8)(0xF & ((11[(uu16 *) &Y[i]])>>5));
		pk[i*18+13] = pk[i*18+13] | (u8)((0xF&(12[(uu16 *) &Y[i]]))<<4);

		pk[i*18+14] = (u8)(0x1F & ((12[(uu16 *) &Y[i]])>>4));
		pk[i*18+14] = pk[i*18+14] | (u8)((0x13&(5[(uu16 *) &Y[i]]))<<5);

		pk[i*18+15] = (u8)(0x3F & ((13[(uu16 *) &Y[i]])>>3));
		pk[i*18+15] = pk[i*18+15] | (u8)((0x3&(14[(uu16 *) &Y[i]]))<<6);

		pk[i*18+16] = (u8)(0x7F & ((14[(uu16 *) &Y[i]])>>2));
		pk[i*18+16] = pk[i*18+16] | (u8)((0x1&(15[(uu16 *) &Y[i]]))<<7);

		pk[i*18+17] = (u8)(0xFF & ((15[(uu16 *) &Y[i]])>>1));*/






		pk[i*18+0] = (u8)(0xFF & opi[i][0]);

		pk[i*18+1] = (u8)(0x1 & (opi[i][0]>>8));
		pk[i*18+1] = pk[i*18+1] | (u8)((0x7F&opi[i][1])<<1);

		pk[i*18+2] = (u8)(0x3 & (opi[i][1]>>7));
		pk[i*18+2] = pk[i*18+2] | (u8)((0x3F&opi[i][2])<<2);

		pk[i*18+3] = (u8)(0x7 & (opi[i][2]>>6));
		pk[i*18+3] = pk[i*18+3] | (u8)((0x1F&opi[i][3])<<3);

		pk[i*18+4] = (u8)(0xF & (opi[i][3]>>5));
		pk[i*18+4] = pk[i*18+4] | (u8)((0xF&opi[i][4])<<4);

		pk[i*18+5] = (u8)(0x1F & (opi[i][4]>>4));
		pk[i*18+5] = pk[i*18+5] | (u8)((0x7&opi[i][5])<<5);

		pk[i*18+6] = (u8)(0x3F & (opi[i][5]>>3));
		pk[i*18+6] = pk[i*18+6] | (u8)((0x3&opi[i][6])<<6);

		pk[i*18+7] = (u8)(0x7F & (opi[i][6]>>2));
		pk[i*18+7] = pk[i*18+7] | (u8)((0x1&opi[i][7])<<7);

		pk[i*18+8] = (u8)(0xFF & (opi[i][7]>>1));
		
		pk[i*18+9] = (u8)(0xFF & opi[i][8]);

		pk[i*18+10] = (u8)(0x1 & (opi[i][8]>>8));
		pk[i*18+10] = pk[i*18+10] | (u8)((0x7F&opi[i][9])<<1);

		pk[i*18+11] = (u8)(0x3 & (opi[i][9]>>7));
		pk[i*18+11] = pk[i*18+11] | (u8)(opi[i][10]<<2);

		pk[i*18+12] = (u8)(0x7 & (opi[i][10]>>6));
		pk[i*18+12] = pk[i*18+12] | (u8)((0x1F&opi[i][11])<<3);

		pk[i*18+13] = (u8)(0xF & (opi[i][11]>>5));
		pk[i*18+13] = pk[i*18+13] | (u8)((0xF&opi[i][12])<<4);

		pk[i*18+14] = (u8)(0x1F & (opi[i][12]>>4));
		pk[i*18+14] = pk[i*18+14] | (u8)((0x7&opi[i][13])<<5);

		pk[i*18+15] = (u8)(0x3F & (opi[i][13]>>3));
		pk[i*18+15] = pk[i*18+15] | (u8)((0x3&opi[i][14])<<6);

		pk[i*18+16] = (u8)(0x7F & (opi[i][14]>>2));
		pk[i*18+16] = pk[i*18+16] | (u8)((0x1&opi[i][15])<<7);

		pk[i*18+17] = (u8)(0xFF & (opi[i][15]>>1));


	}
	
	
}



