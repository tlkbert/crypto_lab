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
	/* inv ARK with the key of round 4 which have been generated at 
	the end of round 3 and used for round 4*/
	/*prev_aes128_round_key(key, prev_key, 3);
	for (i = 0 ; i < 16; i++) {
		state[i] = state[i] ^ prev_key[i];
	}*/
}

void aes_part_decrypt_byte(uint8_t state_byte, uint8_t key_byte) {
	state_byte ^= key_byte;
	state_byte = Sinv[state_byte];
	}

void attack(uint8_t plaintext[256][AES_BLOCK_SIZE]) {
	int i, j, key_guess_byte;
	uint8_t key_guess[16];
	
	//for (key_guess_byte = 0; key_guess_byte < 256; key_guess_byte++) {
		//build the key
		for (i = 1; i < 16; i++) {
			key_guess[i] = 0;
		}
		key_guess[0] = 0x47;
		for (i = 0; i < 256; i++) {
			aes_part_decrypt(plaintext[i], key_guess);
		}
		if (distinguisher(plaintext) == 1) {
			printf("the key gess byte is: %02X\n", key_guess[0]);
		}
	//}
}



