#include "aes-128_enc.h"
#include <stdio.h>

//partial decryption by 1/2 round of one state byte, given one byte of the key

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

	/* inv ARK with the key of round 4 which have been generated at 
	the end of round 3 and used for round 4*/
	prev_aes128_round_key(key, prev_key, 3);
	for (i = 0 ; i < 16; i++) {
		state[i] = state[i] ^ prev_key[i];
	}
}

void aes_part_decrypt_byte(uint8_t state_byte, uint8_t key_byte) {
	state_byte = state_byte ^ key_byte;
	state_byte = Sinv[state_byte];
}
