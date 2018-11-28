#include "aes-128_enc.h"
#include <stdio.h>

//partial decryption by 1/2 round of one state byte, given one byte of the key

uint8_t aes_part_decrypt_byte (uint8_t state_byte, uint8_t key_byte) {
	uint8_t prev_state = key_byte ^ Sinv[state_byte];
	return (prev_state);
}
