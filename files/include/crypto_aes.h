#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H

#include <stdbool.h>

bool crypto_aes_init(unsigned char *key_data, int key_data_len);

unsigned char *crypto_aes_encrypt(unsigned char *plaintext, int *len);
unsigned char *crypto_aes_decrypt(unsigned char *ciphertext, int *len);

#endif
