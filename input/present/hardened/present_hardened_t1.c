/******************************************************************************
Written and Copyright (C) by Dirk Klose
and the EmSec Embedded Security group of Ruhr-Universitaet Bochum.
All rights reserved.

Contact lightweight@crypto.rub.de for comments & questions.
This program is free software; You may use it or parts of it or
modifiy it under the following terms:

(1) Usage and/or redistribution and/or modification of the software
or parts of the software is permitted for non-commercial use only.

(2a) If this software or parts are used as part of a new software, you
must license the entire work, as a whole, under this License to anyone
who comes into possession of a copy. This License will therefore
apply, to the whole of the work, and all its parts, regardless of how
they are packaged.

(2b) You may expand this license by your own license. In this case this
license still applies to the software as mentioned in (2a) and must
not be changed. The expansion must be clearly recognizable as such. In
any case of collision between the license and the expansion the
license is superior to the expansion.

(3) If this software or parts are used as part of a new software, you
must provide equivalent access to the source code of the entire work,
as a whole, to anyone who comes into possession of a copy, in the same
way through the same place at no further charge, as for the binary
version.

(4) This program is distributed in the hope that it will be useful,
but   WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
(5) These notices must be retained in any copies of any part of this
documentation and/or software.

(6) If this software is used credit must be given to the
"Embedded Security Group of Ruhr-Universitaet Bochum, Germany" as
the authors of the parts of the software used. This can be in the form
of a textual message at program startup or  at *beginning* of the
documentation (online or textual) provided with the package.

If you are interested in a commercial use
please contact '''lightweigth@crypto.rub.de'''
******************************************************************************/

/*
Algorithm: PRESENT6480
Hardening technique: statement counters (T1)
Details:
  - each statement of the source code is counted as it is executed
  - after each statement the counter is compared with the expected value
  - each code block (e.g. function call, if/else/then or for loop) has
    its own statement counters.
  - Based on this paper:
    https://hal.inria.fr/file/index/docid/1059201/filename/llncs.pdf

  Problems:
  - the code blocks that are executed only in certain cases (e.g.
    invalid user input) the statement counters may provide wrong
    count values. Such blocks need to be carefully counted or skipped
    entirely.
*/

// Include-file
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define DECL_INIT(cnt, x) int cnt = x;
#define CHECK_INCR(cnt, x) cnt == x ? cnt += 1 : error();
#define CHECK_INCR_FUNC(cnt1, x1, cnt2, x2) (cnt1 == x1) && (cnt2 == x2) ? cnt2 += 1 : error();
#define RESET_CNT(cnt_while, val) (cnt_while == 1 || cnt_while == val) ? cnt_while = 1 : error();
#define CHECK_LOOP_INCR(cnt_loop,x) (cnt_loop == x) ? cnt_loop += 1 : error();
#define CHECK_LOOP_END(cnt_loop, val) if (cnt_loop != val) error();
#define CHECK_END_IF(cnt_then, x) if ((cnt_then != x) && (cnt_then != 1)) error();
// #define CHECK_END_IF_ELSE(cnt_then, cnt_else, b, x, y) if(! ((cnt_then == x && cnt_else== 0 && b) || (cnt_else == y && cnt_then == 0 && !b))) error();
// #define CHECK_INCR_COND(b, cnt, val, cond) (b = (((cnt)++ != val) ? error() : cond))

void error() {
	fprintf(stderr, "HARDERR T1 The algorithm failed to execute properly\n");
  exit(-1);
}

void encryption(uint8_t *plaintext, volatile uint8_t *state, uint8_t *key, int *encrypt_cnt) {
	CHECK_INCR(*encrypt_cnt,1);
	const uint8_t sBox4[] =	{0xc,0x5,0x6,0xb,0x9,0x0,0xa,0xd,0x3,0xe,0xf,0x8,0x4,0x7,0x1,0x2};
	CHECK_INCR(*encrypt_cnt,2);
	//	Counter
	uint8_t i = 0;
	CHECK_INCR(*encrypt_cnt,3);
	//	pLayer variables
	uint8_t position = 0;
	CHECK_INCR(*encrypt_cnt,4);
	uint8_t element_source = 0;
	CHECK_INCR(*encrypt_cnt,5);
	uint8_t bit_source = 0;
	CHECK_INCR(*encrypt_cnt,6);
	uint8_t element_destination	= 0;
	CHECK_INCR(*encrypt_cnt,7);
	uint8_t bit_destination	= 0;
	CHECK_INCR(*encrypt_cnt,8);
	uint8_t temp_pLayer[8];
	CHECK_INCR(*encrypt_cnt,9);
	//	Key scheduling variables
	uint8_t round;
	CHECK_INCR(*encrypt_cnt,10);
	uint8_t save1;
	CHECK_INCR(*encrypt_cnt,11);
	uint8_t save2;
	CHECK_INCR(*encrypt_cnt,12);
	uint8_t j=0;
	CHECK_INCR(*encrypt_cnt,13);
	//	****************** Set up state **************************

	DECL_INIT(while_cnt_one,1);
	CHECK_INCR(*encrypt_cnt,14);
	DECL_INIT(while_loop_cnt_one,0);
	CHECK_INCR(*encrypt_cnt,15);
	while (j<8) {
		RESET_CNT(while_cnt_one,4);
		CHECK_LOOP_INCR(while_loop_cnt_one,j);
		CHECK_INCR(while_cnt_one,1);
		state[j] = plaintext[j];
		CHECK_INCR(while_cnt_one,2);
		j++;
		CHECK_INCR(while_cnt_one,3);
	}
	CHECK_INCR(*encrypt_cnt,16);
	CHECK_LOOP_END(while_loop_cnt_one,8)
	CHECK_INCR(*encrypt_cnt,17);
	//	****************** Encryption **************************
	round=0;
	CHECK_INCR(*encrypt_cnt,18);
	DECL_INIT(while_cnt_two,1);
	CHECK_INCR(*encrypt_cnt,19);
	DECL_INIT(while_loop_cnt_two,0);
	CHECK_INCR(*encrypt_cnt,20);
	while (round<31) {
		RESET_CNT(while_cnt_two,49);
		CHECK_LOOP_INCR(while_loop_cnt_two,round);
		CHECK_INCR(while_cnt_two,1);
		//	****************** addRoundkey *************************
		i=0;
		CHECK_INCR(while_cnt_two,2);
		DECL_INIT(while_cnt_three,1);
		CHECK_INCR(while_cnt_two,3);
		DECL_INIT(while_loop_cnt_three,0);
		CHECK_INCR(while_cnt_two,4);
		while (i<=7) {
			RESET_CNT(while_cnt_three,4);
			CHECK_LOOP_INCR(while_loop_cnt_three,i);
			CHECK_INCR(while_cnt_three,1);
			state[i] = state[i] ^ key[i+2];
			CHECK_INCR(while_cnt_three,2);
			i++;
			CHECK_INCR(while_cnt_three,3);
		}
		CHECK_INCR(while_cnt_two,5);
		CHECK_LOOP_END(while_loop_cnt_three,8)
		CHECK_INCR(while_cnt_two,6);
		//	****************** sBox ********************************
		DECL_INIT(while_cnt_four,1);
		CHECK_INCR(while_cnt_two,7);
		DECL_INIT(while_loop_cnt_four,0);
		CHECK_INCR(while_cnt_two,8);
		i = 0;
		CHECK_INCR(while_cnt_two,9);
		while(i<8) {
			RESET_CNT(while_cnt_four,4);
			CHECK_LOOP_INCR(while_loop_cnt_four,i);
			CHECK_INCR(while_cnt_four,1);
			state[i] = sBox4[state[i]>>4]<<4 | sBox4[state[i] & 0xF];
			CHECK_INCR(while_cnt_four,2);
			i++;
			CHECK_INCR(while_cnt_four,3);
		}
		CHECK_INCR(while_cnt_two,10);
		CHECK_LOOP_END(while_loop_cnt_four,8)
		CHECK_INCR(while_cnt_two,11);
		//	****************** pLayer ******************************
		i = 0;
		CHECK_INCR(while_cnt_two,12);
		DECL_INIT(while_cnt_five,1);
		CHECK_INCR(while_cnt_two,13);
		DECL_INIT(while_loop_cnt_five,0);
		CHECK_INCR(while_cnt_two,14);
		while (i<8) {
			RESET_CNT(while_cnt_five,4);
			CHECK_LOOP_INCR(while_loop_cnt_five,i);
			CHECK_INCR(while_cnt_five,1);
			temp_pLayer[i] = 0;
			CHECK_INCR(while_cnt_five,2);
			i++;
			CHECK_INCR(while_cnt_five,3);
		}
		CHECK_INCR(while_cnt_two,15);
		CHECK_LOOP_END(while_loop_cnt_five,8)
		CHECK_INCR(while_cnt_two,16);
		i = 0;
		CHECK_INCR(while_cnt_two,17);
		DECL_INIT(while_cnt_six,1);
		CHECK_INCR(while_cnt_two,18);
		DECL_INIT(while_loop_cnt_six,0);
		CHECK_INCR(while_cnt_two,19);
		while(i<64) {
			RESET_CNT(while_cnt_six,12);
			CHECK_LOOP_INCR(while_loop_cnt_six,i);
			CHECK_INCR(while_cnt_six,1);
			position = (16*i) % 63;			//Artithmetic calculation of the pLayer
			CHECK_INCR(while_cnt_six,2);
			DECL_INIT(cnt_ifthen_one,1);
			CHECK_INCR(while_cnt_six,3);
			if(i == 63) {	//exception for bit 63
				CHECK_INCR(cnt_ifthen_one,1);
				position = 63;
				CHECK_INCR(cnt_ifthen_one,2);
			}
			CHECK_INCR(while_cnt_six,4);
			CHECK_END_IF(cnt_ifthen_one,3);
			CHECK_INCR(while_cnt_six,5);
			element_source		= i / 8;
			CHECK_INCR(while_cnt_six,6);
			bit_source 			= i % 8;
			CHECK_INCR(while_cnt_six,7);
			element_destination	= position / 8;
			CHECK_INCR(while_cnt_six,8);
			bit_destination 	= position % 8;
			CHECK_INCR(while_cnt_six,9);
			temp_pLayer[element_destination] |= ((state[element_source]>>bit_source) & 0x1) << bit_destination;
			CHECK_INCR(while_cnt_six,10);
			i++;
			CHECK_INCR(while_cnt_six,11);
		}
		CHECK_INCR(while_cnt_two,20);
		CHECK_LOOP_END(while_loop_cnt_six,64)
		CHECK_INCR(while_cnt_two,21);
		i = 0;
		CHECK_INCR(while_cnt_two,22);
		DECL_INIT(while_cnt_seven,1);
		CHECK_INCR(while_cnt_two,23);
		DECL_INIT(while_loop_cnt_seven,0);
		CHECK_INCR(while_cnt_two,24);
		while (i<=7) {
			RESET_CNT(while_cnt_seven,4);
			CHECK_LOOP_INCR(while_loop_cnt_seven,i);
			CHECK_INCR(while_cnt_seven,1);
			state[i] = temp_pLayer[i];
			CHECK_INCR(while_cnt_seven,2);
			i++;
			CHECK_INCR(while_cnt_seven,3);
		}
		CHECK_INCR(while_cnt_two,25);
		CHECK_LOOP_END(while_loop_cnt_seven,8)
		CHECK_INCR(while_cnt_two,26);

		//	****************** End pLayer **************************
		//	****************** Key Scheduling **********************
		save1  = key[0];
		CHECK_INCR(while_cnt_two,27);
		save2  = key[1];
		CHECK_INCR(while_cnt_two,28);
		i = 0;
		CHECK_INCR(while_cnt_two,29);
		DECL_INIT(while_cnt_eight,1);
		CHECK_INCR(while_cnt_two,30);
		DECL_INIT(while_loop_cnt_eight,0);
		CHECK_INCR(while_cnt_two,31);
		while(i<8) {
			RESET_CNT(while_cnt_eight,4);
			CHECK_LOOP_INCR(while_loop_cnt_eight,i);
			CHECK_INCR(while_cnt_eight,1);
			key[i] = key[i+2];
			CHECK_INCR(while_cnt_eight,2);
			i++;
			CHECK_INCR(while_cnt_eight,3);
		}
		CHECK_INCR(while_cnt_two,32);
		CHECK_LOOP_END(while_loop_cnt_eight,8)
		CHECK_INCR(while_cnt_two,33);
		key[8] = save1;
		CHECK_INCR(while_cnt_two,34);
		key[9] = save2;
		CHECK_INCR(while_cnt_two,35);
		i = 0;
		CHECK_INCR(while_cnt_two,36);
		save1 = key[0] & 7;	//61-bit left shift
		CHECK_INCR(while_cnt_two,37);			// CORRECT UNTIL HERE
		DECL_INIT(while_cnt_nine,1);
		CHECK_INCR(while_cnt_two,38);
		DECL_INIT(while_loop_cnt_nine,0);
		CHECK_INCR(while_cnt_two,39);
		while (i<9) {
			RESET_CNT(while_cnt_nine,4);
			CHECK_LOOP_INCR(while_loop_cnt_nine,i);
			CHECK_INCR(while_cnt_nine,1);
			key[i] = key[i] >> 3 | key[i+1] << 5;
			CHECK_INCR(while_cnt_nine,2);
			i++;
			CHECK_INCR(while_cnt_nine,3);
		}
		CHECK_INCR(while_cnt_two,40);
		CHECK_LOOP_END(while_loop_cnt_nine,9)
		CHECK_INCR(while_cnt_two,41);
		key[9] = key[9] >> 3 | save1 << 5;
		CHECK_INCR(while_cnt_two,42);

		key[9] = sBox4[key[9]>>4]<<4 | (key[9] & 0xF);	//S-Box application
		CHECK_INCR(while_cnt_two,43);
		DECL_INIT(cnt_ifthen_two,1);
		CHECK_INCR(while_cnt_two,44);
		if((round+1) % 2 == 1) {	//round counter addition
			CHECK_INCR(cnt_ifthen_two,1);
			key[1] ^= 128;
			CHECK_INCR(cnt_ifthen_two,2);
		}
		CHECK_INCR(while_cnt_two,45);
		CHECK_END_IF(cnt_ifthen_two,3);
		CHECK_INCR(while_cnt_two,46);
		key[2] = ((((round+1)>>1) ^ (key[2] & 15)) | (key[2] & 240));
		CHECK_INCR(while_cnt_two,47);
		//	****************** End Key Scheduling ******************
		round++;
		CHECK_INCR(while_cnt_two,48);
	}
	CHECK_INCR(*encrypt_cnt,21);
	CHECK_LOOP_END(while_loop_cnt_two,31)
	CHECK_INCR(*encrypt_cnt,22);
	//	****************** addRoundkey *************************
	i = 0;
	CHECK_INCR(*encrypt_cnt,23);
	DECL_INIT(while_cnt_ten,1);
	CHECK_INCR(*encrypt_cnt,24);
	DECL_INIT(while_loop_cnt_ten,0);
	CHECK_INCR(*encrypt_cnt,25);
	while(i<=7) {	//final key XOR
		RESET_CNT(while_cnt_ten,4);
		CHECK_LOOP_INCR(while_loop_cnt_ten,i);
		CHECK_INCR(while_cnt_ten,1);
		state[i] = state[i] ^ key[i+2];
		CHECK_INCR(while_cnt_ten,2);
		i++;
		CHECK_INCR(while_cnt_ten,3);
	}
	CHECK_INCR(*encrypt_cnt,26);
	CHECK_LOOP_END(while_loop_cnt_ten,8)
	CHECK_INCR(*encrypt_cnt,27);
	//	****************** End addRoundkey *********************
	//	****************** End Encryption  **********************
}



int main(int argc, char *argv[]) {
	DECL_INIT(main_cnt,1);
  DECL_INIT(cnt_ifthen_main_one,1);
  CHECK_INCR(main_cnt,1);
	if (argc<3) {
    CHECK_INCR(cnt_ifthen_main_one,1);
		fprintf(stderr, "ERROR: Wrong number of arguments\n");
    CHECK_INCR(cnt_ifthen_main_one,2);
	  exit(-1);
	}
  CHECK_INCR(main_cnt,2);

	uint8_t key[10];	// 10 bytes = 80 bits
  CHECK_INCR(main_cnt,3);
	uint8_t plaintext[8];	// 8 bytes = 64 bits
  CHECK_INCR(main_cnt,4);

  CHECK_INCR(main_cnt,5);
	uint8_t i = 0, k = 0, t = 0;
  CHECK_INCR(main_cnt,6);

	// read 20 characters of key in hex (first argument)
  DECL_INIT(while_cnt_main_one,1);
  CHECK_INCR(main_cnt,7);
  DECL_INIT(while_loop_cnt_main_one,0);
  CHECK_INCR(main_cnt,8);
	while (k < 10) {
    RESET_CNT(while_cnt_main_one,4);
    CHECK_LOOP_INCR(while_loop_cnt_main_one,k);
    CHECK_INCR(while_cnt_main_one,1);
    sscanf(&argv[1][k * 2], "%2hhx", &key[k]);
    CHECK_INCR(while_cnt_main_one,2);
    k++;
    CHECK_INCR(while_cnt_main_one,3);
  }
  CHECK_INCR(main_cnt,9);
  CHECK_LOOP_END(while_loop_cnt_main_one,10)
  CHECK_INCR(main_cnt,10);

	// read 16 characters of plaintext in hex (second argument)
  DECL_INIT(while_cnt_main_two,1);
  CHECK_INCR(main_cnt,11);
  DECL_INIT(while_loop_cnt_main_two,0);
  CHECK_INCR(main_cnt,12);
	while (t < 8) {
    RESET_CNT(while_cnt_main_two,4);
    CHECK_LOOP_INCR(while_loop_cnt_main_two,t);
    CHECK_INCR(while_cnt_main_two,1);
    sscanf(&argv[2][t * 2], "%2hhx", &plaintext[t]);
    CHECK_INCR(while_cnt_main_two,2);
    t++;
    CHECK_INCR(while_cnt_main_two,3);
  }
  CHECK_INCR(main_cnt,13);
  CHECK_LOOP_END(while_loop_cnt_main_two,8)
  CHECK_INCR(main_cnt,14);

	// Input values
  CHECK_INCR(main_cnt,15);
	volatile uint8_t state[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  CHECK_INCR(main_cnt,16);

  DECL_INIT(encrypt_cnt,1);
  CHECK_INCR(main_cnt,17);
  encryption(plaintext, state, key, &encrypt_cnt);
  CHECK_INCR_FUNC(encrypt_cnt,28,main_cnt,18);
  i=0;
  CHECK_INCR(main_cnt,19);

  DECL_INIT(while_cnt,1);
  CHECK_INCR(main_cnt,20);
  DECL_INIT(while_loop_cnt,0);
  CHECK_INCR(main_cnt,21);
  while (i < 8) {
    //	****************** BEGIN PRINTING FOR DEBUG *********************
    RESET_CNT(while_cnt,4);
    CHECK_LOOP_INCR(while_loop_cnt,i);
    CHECK_INCR(while_cnt,1);
    printf("0x%02x ",state[i]);
    CHECK_INCR(while_cnt,2);
    i++;
    CHECK_INCR(while_cnt,3);
  }
  CHECK_INCR(main_cnt,22);
  CHECK_LOOP_END(while_loop_cnt,8)
  //	****************** END PRINTING FOR DEBUG *********************
  printf("\n");
  CHECK_INCR(main_cnt,23);
  return 0;
}
