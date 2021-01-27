#include <openssl/evp.h>

#include "log.h"

#include "crypto_aes.h"

static EVP_CIPHER_CTX *e_ctx;
static EVP_CIPHER_CTX *d_ctx;

bool crypto_aes_init(unsigned char *key_data, int key_data_len)
{
	int i, nrounds = 5;
	unsigned char key[32], iv[32];

	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL, key_data, key_data_len, nrounds, key, iv);
	if (i != 32) {
		log_error("Key size is %d bits - should be 256 bits", i);
		return false;
	}

	EVP_CIPHER_CTX_init(e_ctx);
	EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_CIPHER_CTX_init(d_ctx);
	EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

	return true;
}

unsigned char *crypto_aes_encrypt(unsigned char *plaintext, int *len)
{
	int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
	unsigned char *ciphertext = malloc(c_len);

	EVP_EncryptInit_ex(e_ctx, NULL, NULL, NULL, NULL);
	EVP_EncryptUpdate(e_ctx, ciphertext, &c_len, plaintext, *len);
	EVP_EncryptFinal_ex(e_ctx, ciphertext+c_len, &f_len);

	*len = c_len + f_len;
	return ciphertext;
}

unsigned char *crypto_aes_decrypt(unsigned char *ciphertext, int *len)
{
	int p_len = *len, f_len = 0;
	unsigned char *plaintext = malloc(p_len);

	EVP_DecryptInit_ex(d_ctx, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(d_ctx, plaintext, &p_len, ciphertext, *len);
	EVP_DecryptFinal_ex(d_ctx, plaintext+p_len, &f_len);

	*len = p_len + f_len;
	return plaintext;
}
