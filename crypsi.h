/*
The MIT License (MIT)

Copyright (c) 2023 The TelkomDev Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef CRYPSI_H
#define CRYPSI_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

#define HEX_STRINGS "0123456789abcdef"
#define AES_GCM_IV_SIZE 12
#define AES_GCM_TAG_SIZE 16
#define HMAC_KEY_MIN_SIZE 32

static const unsigned char HEX_TABLE[][2] = {
    {0x30, 0}, 
    {0x31, 1}, 
    {0x32, 2}, 
    {0x33, 3}, 
    {0x34, 4}, 
    {0x35, 5}, 
    {0x36, 6}, 
    {0x37, 7}, 
    {0x38, 8}, 
    {0x39, 9}, 
    {0x61, 10}, 
    {0x62, 11}, 
    {0x63, 12}, 
    {0x64, 13}, 
    {0x65, 14}, 
    {0x66, 15}, 
    {0x41, 10}, 
    {0x42, 11}, 
    {0x43, 12}, 
    {0x44, 13}, 
    {0x45, 14}, 
    {0x46, 15}};

enum crypsi_aes_key {
    CRYPSI_AES_128_KEY = 16,
    CRYPSI_AES_192_KEY = 24,
    CRYPSI_AES_256_KEY = 32
};

enum crypsi_aes_mode {
    CRYPSI_AES_CBC_MODE,
    CRYPSI_AES_GCM_MODE,
};

enum crypsi_digest_alg {
    CRYPSI_MD5,
    CRYPSI_SHA1,
    CRYPSI_SHA256,
    CRYPSI_SHA384,
    CRYPSI_SHA512,
};

#ifdef __cplusplus
extern "C" {
#endif

// utilities
int hexencode(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);
int hexdecode(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);
unsigned char find_hex_val(unsigned char hx);

// AES
static int crypsi_aes_cbc_encrypt(enum crypsi_aes_key aes_key_size, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len);
static int crypsi_aes_cbc_decrypt(enum crypsi_aes_key aes_key_size, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len);

static int crypsi_aes_gcm_encrypt(enum crypsi_aes_key aes_key_size, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len);
static int crypsi_aes_gcm_decrypt(enum crypsi_aes_key aes_key_size, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len);

// AES CBC
int crypsi_aes_128_cbc_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_aes_192_cbc_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_aes_256_cbc_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);

int crypsi_aes_128_cbc_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_aes_192_cbc_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_aes_256_cbc_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);

// AES GCM
int crypsi_aes_128_gcm_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_aes_192_gcm_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_aes_256_gcm_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);

int crypsi_aes_128_gcm_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_aes_192_gcm_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_aes_256_gcm_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len);

// message digest
static int crypsi_digest(enum crypsi_digest_alg alg, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_md5(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_sha1(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_sha256(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_sha384(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_sha512(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);

// hmac
static int crypsi_hmac(enum crypsi_digest_alg alg, const unsigned char* key, 
    const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_hmac_md5(const unsigned char* key, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_hmac_sha1(const unsigned char* key, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_hmac_sha256(const unsigned char* key, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_hmac_sha384(const unsigned char* key, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_hmac_sha512(const unsigned char* key, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len);

#ifdef __cplusplus
}
#endif

unsigned char find_hex_val(unsigned char hx) {
    char c = 0x0;
     for (int j = 0; j < sizeof(HEX_TABLE); j++) {
        if (hx == HEX_TABLE[j][0]) {
            c = HEX_TABLE[j][1];
            break;
        }
    }
    return c;
}

int hexencode(const unsigned char* message, size_t message_len, 
    unsigned char** dst, unsigned int* dst_len) {
    
    int ret = -1;
    int result_len = message_len*2+1;
    unsigned char* _dst = (unsigned char*) malloc(result_len);
    if (_dst == NULL) {
        goto cleanup;
    }

    *dst_len = result_len-1;

    for (int i = 0; i < message_len; i++ ) {
        _dst[i+i] = HEX_STRINGS[message[i] >> 0x4];
        _dst[i+i+1] = HEX_STRINGS[message[i] & 0xf];
    }

    _dst[result_len-1] = 0x0;
    *dst = _dst;

    ret = 0;

    cleanup:
        return ret;
}

int hexdecode(const unsigned char* message, size_t message_len, 
    unsigned char** dst, unsigned int* dst_len) {
    
    int ret = -1;
    int result_len = message_len/2+1;
    unsigned char* _dst = (unsigned char*) malloc(result_len);
    if (_dst == NULL) {
        goto cleanup;
    }

    *dst_len = result_len-1;

    for (int i = 0; i < result_len - 1; i++ ) {
        unsigned char ca = find_hex_val(message[i+i]);
        unsigned char cb = find_hex_val(message[i+i+1]);

        _dst[i] = (ca << 4) | cb;
    }

    _dst[result_len-1] = 0x0;
    *dst = _dst;

    ret = 0;

    cleanup:
        return ret;
}

// MESSAGE DIGEST
static int crypsi_digest(enum crypsi_digest_alg alg, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    EVP_MD_CTX* mdctx;
    EVP_MD* md;

    int ret = -1;
    unsigned int dst_len_tmp = 0;
    unsigned char* dst_tmp;

    switch (alg) {
    case CRYPSI_MD5:
        md = (EVP_MD*) EVP_md5();
        break;
    case CRYPSI_SHA1:
        md = (EVP_MD*) EVP_sha1();
        break;
    case CRYPSI_SHA256:
        md = (EVP_MD*) EVP_sha256();
        break;
    case CRYPSI_SHA384:
        md = (EVP_MD*) EVP_sha384();
        break;
    case CRYPSI_SHA512:
        md = (EVP_MD*) EVP_sha512();
        break;
    default:
        return ret;
    }

    if((mdctx = EVP_MD_CTX_new()) == NULL) {
        goto cleanup;
    }

    if(1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        goto cleanup;
    }

    if(1 != EVP_DigestUpdate(mdctx, message, message_len)) {
        goto cleanup;
    }

    if((dst_tmp = (unsigned char *) OPENSSL_malloc(EVP_MD_size(md))) == NULL) {
        goto cleanup;
    }

    if(1 != EVP_DigestFinal_ex(mdctx, dst_tmp, &dst_len_tmp)) {
        goto cleanup;
    }

    // encode to hex
    if(hexencode(dst_tmp, dst_len_tmp, dst, dst_len) != 0) {
        goto cleanup;
    }

    ret = 0;

    cleanup:
        EVP_MD_CTX_free(mdctx);
        OPENSSL_free(dst_tmp);
        return ret;
}

int crypsi_md5(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_digest(CRYPSI_MD5, message, message_len, dst, dst_len);
}

int crypsi_sha1(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_digest(CRYPSI_SHA1, message, message_len, dst, dst_len);
}

int crypsi_sha256(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_digest(CRYPSI_SHA256, message, message_len, dst, dst_len);
}

int crypsi_sha384(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_digest(CRYPSI_SHA384, message, message_len, dst, dst_len);
}

int crypsi_sha512(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_digest(CRYPSI_SHA512, message, message_len, dst, dst_len);
}

// HMAC
static int crypsi_hmac(enum crypsi_digest_alg alg, const unsigned char* key, 
    const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    
    EVP_MD_CTX* mdctx;
    EVP_MD* md;
    EVP_PKEY* pkey;

    int ret = -1;
    size_t dst_len_tmp = 0;
    unsigned char* dst_tmp;

    if (strlen((char*) key) < HMAC_KEY_MIN_SIZE) {
        return ret;
    }

    switch (alg) {
    case CRYPSI_MD5:
        md = (EVP_MD*) EVP_md5();
        break;
    case CRYPSI_SHA1:
        md = (EVP_MD*) EVP_sha1();
        break;
    case CRYPSI_SHA256:
        md = (EVP_MD*) EVP_sha256();
        break;
    case CRYPSI_SHA384:
        md = (EVP_MD*) EVP_sha384();
        break;
    case CRYPSI_SHA512:
        md = (EVP_MD*) EVP_sha512();
        break;
    default:
        return ret;
    }

    if((mdctx = EVP_MD_CTX_new()) == NULL) {
        goto cleanup;
    }

    if(!(pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, strlen((char*) key)))) {
        goto cleanup;
    }

    if(1 != EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey)) {
        goto cleanup;
    }

    if(1 != EVP_DigestSignUpdate(mdctx, message, message_len)) {
        goto cleanup;
    }

    if((dst_tmp = (unsigned char*) OPENSSL_malloc(EVP_MD_size(md))) == NULL) {
        goto cleanup;
    }

    if(1 != EVP_DigestSignFinal(mdctx, dst_tmp, &dst_len_tmp)) {
        goto cleanup;
    }

    // encode to hex
    if(hexencode(dst_tmp, dst_len_tmp, dst, dst_len) != 0) {
        goto cleanup;
    }

    ret = 0;

    cleanup:
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        OPENSSL_free(dst_tmp);
        return ret;
}

int crypsi_hmac_md5(const unsigned char* key, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_hmac(CRYPSI_MD5, key, message, message_len, dst, dst_len);
}

int crypsi_hmac_sha1(const unsigned char* key, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_hmac(CRYPSI_SHA1, key, message, message_len, dst, dst_len);
}

int crypsi_hmac_sha256(const unsigned char* key, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_hmac(CRYPSI_SHA256, key, message, message_len, dst, dst_len);
}

int crypsi_hmac_sha384(const unsigned char* key, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_hmac(CRYPSI_SHA384, key, message, message_len, dst, dst_len);
}

int crypsi_hmac_sha512(const unsigned char* key, const unsigned char* message, 
    size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_hmac(CRYPSI_SHA512, key, message, message_len, dst, dst_len);
}

// AES
static int crypsi_aes_cbc_encrypt(enum crypsi_aes_key aes_key_size, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER* cipher;

    int ret = -1;
    int dst_len_tmp = 0;
    int ciphertext_len = 0;
    int result_len_raw = 0;
    unsigned char* dst_tmp_raw; 
    unsigned char* dst_tmp;
    unsigned char iv[AES_BLOCK_SIZE];

    // After padding and encrypting data, the size of the ciphertext is plaintext_size + (block_size - plaintext_size % block_size)
    int raw_ciphertext_len = data_len + (AES_BLOCK_SIZE - data_len%AES_BLOCK_SIZE) + 1;

    switch (aes_key_size) {
    case CRYPSI_AES_128_KEY:
        if (strlen((char*) key) != CRYPSI_AES_128_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_128_cbc();
        break;
    case CRYPSI_AES_192_KEY:
        if (strlen((char*) key) != CRYPSI_AES_192_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_192_cbc();
        break;
    case CRYPSI_AES_256_KEY:
        if (strlen((char*) key) != CRYPSI_AES_256_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_256_cbc();
        break;
    default:
        return ret;
    }

    if((dst_tmp_raw = (unsigned char*) malloc(raw_ciphertext_len)) == NULL) {
        goto cleanup;
    }

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        goto cleanup;
    }
    
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        goto cleanup;
    }
    
    if(EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        goto cleanup;
    }

    if(EVP_EncryptUpdate(ctx, dst_tmp_raw, &dst_len_tmp, data, data_len) != 1) {
        goto cleanup;
    }
    
    ciphertext_len = dst_len_tmp;

    if(EVP_EncryptFinal_ex(ctx, dst_tmp_raw + dst_len_tmp, &dst_len_tmp) != 1) {
        goto cleanup;
    }

    ciphertext_len += dst_len_tmp;
    dst_tmp_raw[raw_ciphertext_len-1] = 0x0;

    result_len_raw = ciphertext_len + sizeof(iv) + 1;

    if((dst_tmp = (unsigned char*) malloc(result_len_raw)) == NULL) {
        goto cleanup;
    }

    // concat iv with cipher text
    memcpy(dst_tmp, iv, sizeof(iv));
    memcpy(dst_tmp+sizeof(iv), dst_tmp_raw, raw_ciphertext_len-1);

    dst_tmp[result_len_raw-1] = 0x0;
    
    // encode to hex
    if(hexencode(dst_tmp, result_len_raw-1, dst, dst_len) != 0) {
        goto cleanup;
    }

    ret = 0;
    
    /* Clean up */
    cleanup:
        EVP_CIPHER_CTX_free(ctx);
        free((void*) dst_tmp);
        free((void*) dst_tmp_raw);

        return ret;
}

static int crypsi_aes_cbc_decrypt(enum crypsi_aes_key aes_key_size, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER* cipher;

    int ret = -1;
    int dst_len_tmp = 0;
    int plaintext_len = 0;
    int raw_ciphertext_len = 0;
    unsigned char* ciphertext_raw; 
    unsigned char* dst_tmp;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char* dst_decode;
    unsigned int dst_decode_len = 0;

    switch (aes_key_size) {
    case CRYPSI_AES_128_KEY:
        if (strlen((char*) key) != CRYPSI_AES_128_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_128_cbc();
        break;
    case CRYPSI_AES_192_KEY:
        if (strlen((char*) key) != CRYPSI_AES_192_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_192_cbc();
        break;
    case CRYPSI_AES_256_KEY:
        if (strlen((char*) key) != CRYPSI_AES_256_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_256_cbc();
        break;
    default:
        return ret;
    }
    
    if(hexdecode(data, data_len, &dst_decode, &dst_decode_len) != 0) {
        goto cleanup;
    }
    
    memcpy(iv, dst_decode, sizeof(iv));

    // After padding and encrypting data, the size of the ciphertext is plaintext_size + (block_size - plaintext_size % block_size)
    raw_ciphertext_len = dst_decode_len - sizeof(iv) + 1;

    if((ciphertext_raw = (unsigned char*) malloc(raw_ciphertext_len)) == NULL) {
        goto cleanup;
    }

    memcpy(ciphertext_raw, dst_decode+sizeof(iv), raw_ciphertext_len);
    ciphertext_raw[raw_ciphertext_len-1] = 0x0;

    if((dst_tmp = (unsigned char*) malloc(raw_ciphertext_len)) == NULL) {
        goto cleanup;
    }
    
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        goto cleanup;
    }
    
    if(EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        goto cleanup;
    }

    if(EVP_DecryptUpdate(ctx, dst_tmp, &dst_len_tmp, ciphertext_raw, raw_ciphertext_len-1) != 1) {
        goto cleanup;
    }
    
    plaintext_len = dst_len_tmp;
    
    if(EVP_DecryptFinal_ex(ctx, dst_tmp + dst_len_tmp, &dst_len_tmp) != 1) {
        goto cleanup;
    }

    plaintext_len += dst_len_tmp;

    if((*dst = (unsigned char*) malloc(plaintext_len+1)) == NULL) {
        goto cleanup;
    }
   
    memcpy(*dst, dst_tmp, plaintext_len);
    // *dst[plaintext_len] = 0x0;

    *dst_len = plaintext_len;

    ret = 0;

    /* Clean up */
    cleanup:
        EVP_CIPHER_CTX_free(ctx);
        free((void*) dst_decode);
        free((void*) ciphertext_raw);
        free((void*) dst_tmp);
        return ret;
}

static int crypsi_aes_gcm_encrypt(enum crypsi_aes_key aes_key_size, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER* cipher;

    int ret = -1;
    int dst_len_tmp = 0;
    int ciphertext_len = 0;
    int result_len_raw = 0;
    unsigned char* dst_tmp_raw; 
    unsigned char* dst_tmp;
    unsigned char iv[AES_GCM_IV_SIZE];
    unsigned char tag[AES_GCM_TAG_SIZE];

    // After padding and encrypting data, the size of the ciphertext is plaintext_size + (block_size - plaintext_size % block_size)
    int raw_ciphertext_len = data_len + (AES_BLOCK_SIZE - data_len%AES_BLOCK_SIZE) + 1;

    switch (aes_key_size) {
    case CRYPSI_AES_128_KEY:
        if (strlen((char*) key) != CRYPSI_AES_128_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_128_gcm();
        break;
    case CRYPSI_AES_192_KEY:
        if (strlen((char*) key) != CRYPSI_AES_192_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_192_gcm();
        break;
    case CRYPSI_AES_256_KEY:
        if (strlen((char*) key) != CRYPSI_AES_256_KEY) {
            return ret;
        }
        
        cipher = (EVP_CIPHER*) EVP_aes_256_gcm();
        break;
    default:
        return ret;
    }

    if((dst_tmp_raw = (unsigned char*) malloc(raw_ciphertext_len)) == NULL) {
        return -1;
    }
    
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        goto cleanup;
    }

    // generate iv
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        goto cleanup;
    }

    if(EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        goto cleanup;
    }

    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, NULL) != 1) {
        goto cleanup;
    }

    if(EVP_EncryptUpdate(ctx, dst_tmp_raw, &dst_len_tmp, data, data_len) != 1) {
        goto cleanup;
    }
    
    ciphertext_len = dst_len_tmp;

    if(EVP_EncryptFinal_ex(ctx, dst_tmp_raw + dst_len_tmp, &dst_len_tmp) != 1) {
        goto cleanup;
    }

    ciphertext_len += dst_len_tmp;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        goto cleanup;
    }

    dst_tmp_raw[ciphertext_len] = 0x0;

    result_len_raw = ciphertext_len + sizeof(iv) + sizeof(tag) + 1;

    if((dst_tmp = (unsigned char*) malloc(result_len_raw)) == NULL) {
        goto cleanup;
    }

    // concat iv and tag with cipher text
    memcpy(dst_tmp, iv, sizeof(iv));
    memcpy(dst_tmp+sizeof(iv), dst_tmp_raw, ciphertext_len);
    memcpy(dst_tmp+ciphertext_len+sizeof(iv), tag, sizeof(tag));

    dst_tmp[result_len_raw-1] = 0x0;
    
    // encode to hex
    if(hexencode(dst_tmp, result_len_raw-1, dst, dst_len) != 0) {
        goto cleanup;
    }

    ret = 0;
    
    /* Clean up */
    cleanup:
        EVP_CIPHER_CTX_free(ctx);
        free((void*) dst_tmp);
        free((void*) dst_tmp_raw);

        return ret;
}

static int crypsi_aes_gcm_decrypt(enum crypsi_aes_key aes_key_size, const unsigned char* key, 
    const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER* cipher;

    int ret = -1;
    int dst_len_tmp = 0;
    int plaintext_len = 0;
    int raw_ciphertext_len = 0;
    unsigned char* ciphertext_raw; 
    unsigned char* dst_tmp;
    unsigned char iv[AES_GCM_IV_SIZE];
    unsigned char tag[AES_GCM_TAG_SIZE];
    unsigned char* dst_decode;
    unsigned int dst_decode_len = 0;
    
    switch (aes_key_size) {
    case CRYPSI_AES_128_KEY:
        if (strlen((char*) key) != CRYPSI_AES_128_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_128_gcm();
        break;
    case CRYPSI_AES_192_KEY:
        if (strlen((char*) key) != CRYPSI_AES_192_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_192_gcm();
        break;
    case CRYPSI_AES_256_KEY:
        if (strlen((char*) key) != CRYPSI_AES_256_KEY) {
            return ret;
        }

        cipher = (EVP_CIPHER*) EVP_aes_256_gcm();
        break;
    default:
        return ret;
    }

    if(hexdecode(data, data_len, &dst_decode, &dst_decode_len) != 0) {
        goto cleanup;
    }
    
    // copy iv
    memcpy(iv, dst_decode, sizeof(iv));

    // After padding and encrypting data, the size of the ciphertext is plaintext_size + (block_size - plaintext_size % block_size)
    raw_ciphertext_len = dst_decode_len - (sizeof(iv)+sizeof(tag)) + 1;

    if((ciphertext_raw = (unsigned char*) malloc(raw_ciphertext_len)) == NULL) {
        goto cleanup;
    }

    // copy raw cipher text
    memcpy(ciphertext_raw, dst_decode+sizeof(iv), raw_ciphertext_len);
    ciphertext_raw[raw_ciphertext_len-1] = 0x0;

    // copy tag
    memcpy(tag, dst_decode+raw_ciphertext_len+sizeof(iv)-1, sizeof(tag));

    if((dst_tmp = (unsigned char*) malloc(raw_ciphertext_len)) == NULL) {
        goto cleanup;
    }

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        goto cleanup;
    }
    
    if(EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag) != 1) {
        goto cleanup;
    }

    if(EVP_DecryptUpdate(ctx, dst_tmp, &dst_len_tmp, ciphertext_raw, raw_ciphertext_len-1) != 1) {
        goto cleanup;
    }
    
    plaintext_len = dst_len_tmp;
    
    if(EVP_DecryptFinal_ex(ctx, dst_tmp + dst_len_tmp, &dst_len_tmp) != 1) {
        goto cleanup;
    }

    plaintext_len += dst_len_tmp;

    if((*dst = (unsigned char*) malloc(plaintext_len+1)) == NULL) {
        goto cleanup;
    }
   
    memcpy(*dst, dst_tmp, plaintext_len);
    // *dst[plaintext_len] = 0x0;

    *dst_len = plaintext_len;

    ret = 0;

    /* Clean up */
    cleanup:
        EVP_CIPHER_CTX_free(ctx);
        free((void*) dst_decode);
        free((void*) ciphertext_raw);
        free((void*) dst_tmp);
        
        return ret;
}

// AES CBC
int crypsi_aes_128_cbc_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_cbc_encrypt(CRYPSI_AES_128_KEY, key, data, data_len, dst, dst_len);
}

int crypsi_aes_192_cbc_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_cbc_encrypt(CRYPSI_AES_192_KEY, key, data, data_len, dst, dst_len);
}

int crypsi_aes_256_cbc_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_cbc_encrypt(CRYPSI_AES_256_KEY, key, data, data_len, dst, dst_len);
}

int crypsi_aes_128_cbc_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_cbc_decrypt(CRYPSI_AES_128_KEY, key, data, data_len, dst, dst_len);
}

int crypsi_aes_192_cbc_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_cbc_decrypt(CRYPSI_AES_192_KEY, key, data, data_len, dst, dst_len);
}

int crypsi_aes_256_cbc_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_cbc_decrypt(CRYPSI_AES_256_KEY, key, data, data_len, dst, dst_len);
}

// AES GCM
int crypsi_aes_128_gcm_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_gcm_encrypt(CRYPSI_AES_128_KEY, key, data, data_len, dst, dst_len);
}

int crypsi_aes_192_gcm_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_gcm_encrypt(CRYPSI_AES_192_KEY, key, data, data_len, dst, dst_len);
}

int crypsi_aes_256_gcm_encrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_gcm_encrypt(CRYPSI_AES_256_KEY, key, data, data_len, dst, dst_len);
}

int crypsi_aes_128_gcm_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_gcm_decrypt(CRYPSI_AES_128_KEY, key, data, data_len, dst, dst_len);
}

int crypsi_aes_192_gcm_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_gcm_decrypt(CRYPSI_AES_192_KEY, key, data, data_len, dst, dst_len);
}

int crypsi_aes_256_gcm_decrypt(const unsigned char* key, const unsigned char* data, 
    size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_aes_gcm_decrypt(CRYPSI_AES_256_KEY, key, data, data_len, dst, dst_len);
}

#endif