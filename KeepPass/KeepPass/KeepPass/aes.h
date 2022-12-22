
#ifndef AES_H
#define AES_H
#define BLOCK_LEN 16
#define BLOCK_SIDE 4

#define AES_IRREDUCIBLE 0x1B

#define AES_128 128
#define AES_192 192
#define AES_256 256

// Substitution Reference
extern unsigned char s_box[256];
extern unsigned char inv_s_box[256];

// Constant matrix for mix columns
extern unsigned char mix_col_mat[BLOCK_SIDE][BLOCK_SIDE];
extern unsigned char inv_mix_col_mat[BLOCK_SIDE][BLOCK_SIDE];

// Perform Galois Field multiplication of two bytes in GF(2^8)
unsigned char galois_mul(unsigned char g1, unsigned char g2);

/*
	AES ENCRYPTION LAYERS
*/

void add_round_key(unsigned char state[BLOCK_SIDE][BLOCK_SIDE], unsigned char subkey[BLOCK_SIDE][BLOCK_SIDE]);
void byte_sub(unsigned char state[BLOCK_SIDE][BLOCK_SIDE]);
void shift_rows(unsigned char state[BLOCK_SIDE][BLOCK_SIDE]);
void mix_cols(unsigned char state[BLOCK_SIDE][BLOCK_SIDE]);

void aes_encrypt_block(unsigned char* in_text, int n,
					   unsigned char subkeys[][BLOCK_SIDE][BLOCK_SIDE], int nr,
					   unsigned char out[BLOCK_LEN]);

int aes_encrypt(unsigned char* in_text, int n,
				 unsigned char* in_key, int keylen,
				 unsigned char** out);

/*
	AES DECRYPTION LAYERS
*/

void inv_add_round_key(unsigned char state[BLOCK_SIDE][BLOCK_SIDE], unsigned char subkey[BLOCK_SIDE][BLOCK_SIDE]);
void inv_byte_sub(unsigned char state[BLOCK_SIDE][BLOCK_SIDE]);
void inv_shift_rows(unsigned char state[BLOCK_SIDE][BLOCK_SIDE]);
void inv_mix_cols(unsigned char state[BLOCK_SIDE][BLOCK_SIDE]);

void aes_decrypt_block(unsigned char* in_cipher,
					   unsigned char subkeys[][BLOCK_SIDE][BLOCK_SIDE], int nr,
					   unsigned char out[BLOCK_LEN]);

int aes_decrypt(unsigned char* in_cipher, int n_blocks,
				 unsigned char* in_key, int keylen,
				 unsigned char **out);

/*
	KEY SCHEDULING
*/
void generate_key_schedule(unsigned char* in_key, int key_len, unsigned char subkeys[][BLOCK_SIDE][BLOCK_SIDE]);
void generate_key_schedule128(unsigned char* in_key, unsigned char subkeys[11][BLOCK_SIDE][BLOCK_SIDE]);		// 0 + 10 rounds

#endif

