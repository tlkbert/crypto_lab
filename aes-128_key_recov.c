#include "aes-128_enc.h"
#include <stdio.h>

//partial decryption by 1/2 round of one state byte, given one byte of the key
/*
void aes_part_decrypt(uint8_t state[AES_BLOCK_SIZE], uint8_t key[AES_128_KEY_SIZE]) {

	int i;
	uint8_t temp;
	uint8_t prev_key[AES_128_KEY_SIZE];
	// inv ARK & inv SB with the key of round 5 generated at the end of round 4
	for (i = 0 ; i < 16; i++) {
		state[i] = state[i] ^ key[i];
		state[i] = Sinv[state[i]];
	}

	//inverse shiftrows
	/* Row 1 */
/*	temp = state[13];
	state[ 13] = state[9];
	state[ 9] = state[ 5];
	state[ 5] = state[ 1];
	state[ 1] = temp;
	/* Row 2 */
/*	temp = state[10];
	state[ 10] = state[2];
	state[ 2] = temp;
	temp = state[14];
	state[ 14] = state[ 6];
	state[6] = temp;
	/* Row 3 */
/*	temp = state[3];
	state[ 3] = state[ 7];
	state[ 7] = state[ 11];
	state[11] = state[15];
	state[ 15] = temp;

	/* inv ARK with the key of round 4 which have been generated at 
	the end of round 3 and used for round 4*/
/*	prev_aes128_round_key(key, prev_key, 3);
	for (i = 0 ; i < 16; i++) {
		state[i] = state[i] ^ prev_key[i];
	}
}*/

void aes_part_decrypt_byte(uint8_t *state_byte, uint8_t key_byte) {
	//printf("before decrypt : %02X\n", state_byte);
	*(state_byte) ^= key_byte;
	*(state_byte) = Sinv[*(state_byte)];
	//printf("after decrypt : %02X\n", state_byte);
}

void attack(uint8_t plaintext[256][AES_BLOCK_SIZE]) {
	int i, j, key_guess_byte;
	uint8_t key;
	//Partial decryption of the 1/2 round and call to the distinguisher
	
	for (key_guess_byte = 0; key_guess_byte < 256; key_guess_byte++) {
		for (i = 0; i < 256; i++) {
			for(j=0;j<16;j++) {
				//printf("plaintext before:%02X\n",plaintext[i][j]);
				aes_part_decrypt_byte(*(plaintext+i+j), (uint8_t)key_guess_byte);
				//printf("plaintext after:%02X\n",plaintext[i][j]);
			}
		}
		distinguisher(plaintext);
	}
}



