#include "aes-128_enc.h"
#include <stdio.h>

uint8_t plaintext_example[AES_BLOCK_SIZE] = {
	0x00, 0x11, 0x22, 0x33,
	0x44, 0x55, 0x66,0x77,
	0x88, 0x99, 0xaa, 0xbb,
	0xcc, 0xdd, 0xee, 0xff
};

uint8_t key[AES_128_KEY_SIZE] = {
	0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f
};

/*uint8_t ciphertext_example[AES_BLOCK_SIZE] = {
	0x69, 0xC4, 0xE0, 0xD8,
	0x6A, 0x7B, 0x04, 0x30,
	0xD8, 0xCD, 0xB7, 0x80,
	0x70, 0xB4, 0xC5, 0x5A
};*/

int main (int argc, char ** argv){
	//Attack implementation
	
	uint8_t plaintexts[256][AES_BLOCK_SIZE];
	uint8_t key_guess[AES_128_KEY_SIZE];
	int i, j;
	// Entering the key guess
	for (i = 0; i < 16; i++) {
		printf("Enter the byte %d of the key guess", i);
		scanf("%02X", &key_guess[i]);
	}
	for (i = 0; i < 256; i++) {
		for (j = 0; j < 16; j++) {
			plaintexts[i][j] = i+j+1;
		}
	} 
	// Queries to the encryption oracle
	for (i = 0; i < 256; i++) {
		aes128_enc(plaintexts[i], key, 4, 0);
	}
	//Partial decryption of the 1/2 round and call to the distinguisher
	for (i = 0; i < 256; i++) {
		aes_part_decrypt(plaintexts[i], key_guess);
	}
	distinguisher(plaintexts);
	return 0;
}

