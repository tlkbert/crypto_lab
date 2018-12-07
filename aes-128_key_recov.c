#include "aes-128_enc.h"
#include <stdio.h>


void aes_part_decrypt(uint8_t state[AES_BLOCK_SIZE], uint8_t key[AES_128_KEY_SIZE]) {

	int i;
	uint8_t temp;
	uint8_t prev_key[AES_128_KEY_SIZE];
	// inv ARK & inv SB with the key of round 5 generated at the end of round 4
	for (i = 0 ; i < 16; i++) {
		state[i] = state[i] ^ key[i];
	}
		//inverse shiftrows
	/* Row 1 */
	temp = state[13];
	state[ 13] = state[9];
	state[ 9] = state[ 5];
	state[ 5] = state[ 1];
	state[ 1] = temp;
	/* Row 2 */
	temp = state[10];
	state[ 10] = state[2];
	state[ 2] = temp;
	temp = state[14];
	state[ 14] = state[ 6];
	state[6] = temp;
	/* Row 3 */
	temp = state[3];
	state[ 3] = state[ 7];
	state[ 7] = state[ 11];
	state[11] = state[15];
	state[ 15] = temp;

	for (i = 0 ; i < 16; i++) {
		state[i] = Sinv[state[i]];
	}
}

void aes_part_decrypt_byte(uint8_t state_byte, uint8_t key_byte) {
	state_byte ^= key_byte;
	state_byte = Sinv[state_byte];
	}
//recover the byte i of the key
uint8_t attack_byte_i(uint8_t plaintext[256][AES_BLOCK_SIZE], uint8_t key_guess[16], int k) {
	int i, j;
	uint8_t to_decrypt[256][16];
	for (i=0;i<256;i++){
		for(j=0;j<16;j++){
			to_decrypt[i][j] = plaintext[i][j];
		}
	} 
	for (i = 0; i < 256; i++) {
		aes_part_decrypt(to_decrypt[i], key_guess);
	}
	if (distinguisher(to_decrypt, k) == 1) {
		return key_guess[k];
	}
	else{
		return 0xff;
	}
}
/*
void aes_key_recovery(uint8_t plaintext[256][AES_BLOCK_SIZE], uint8_t key_guess[16], int k, int valid, uint8_t key_value) {
	//int i, j;
	attack_byte_i(plaintext, key_guess, k, valid, key_value);
}
*/
