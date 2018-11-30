#include "aes-128_enc.h"
#include <stdio.h>

//partial decryption by 1/2 round of one state byte, given one byte of the key

uint8_t aes_part_decrypt (uint8_t state[AES_BLOCK_SIZE], uint8_t key[AES_128_KEY_SIZE]) {
// for the first row (0 to 3)
	int i;
	uint8_t prev_state[AES_BLOCK_SIZE];
	uint8_t temp;

	for (i = 0 ; i < 16; i++) {
		state[i] ^ = key[i]; //ARK inv
		state[i] = Sinv[state[i]; //SB inv
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
	tmp = block[14];
	state[ 14] = state[ 6];
	state[6] = temp;
	/* Row 3 */
	tmp = block[3];
	state[ 3] = state[ 7];
	state[ 7] = state[ 11];
	state[11] = state[15];
	state[ 15] = tmp;

	for (i = 0 ; i < 16; i++) {
		state[i] ^ = key[i]; //ARK inv
		prev_state[i] = state[i]; //copy into prev_state
	}

	return (prev_state);
}
