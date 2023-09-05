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

#include <mysql.h>
#include <string.h>
#include "crypsi.h"

#ifdef __cplusplus
extern "C" {
#endif

// AES 128 GCM encrypt
int mcrypsi_aes_128_gcm_encrypt_init(UDF_INIT* initid, UDF_ARGS* args, char* message);
void mcrypsi_aes_128_gcm_encrypt_deinit(UDF_INIT* initid);
char* mcrypsi_aes_128_gcm_encrypt(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error);

// AES 128 GCM decrypt
int mcrypsi_aes_128_gcm_decrypt_init(UDF_INIT* initid, UDF_ARGS* args, char* message);
void mcrypsi_aes_128_gcm_decrypt_deinit(UDF_INIT* initid);
char* mcrypsi_aes_128_gcm_decrypt(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error);

// AES 192 GCM encrypt
int mcrypsi_aes_192_gcm_encrypt_init(UDF_INIT* initid, UDF_ARGS* args, char* message);
void mcrypsi_aes_192_gcm_encrypt_deinit(UDF_INIT* initid);
char* mcrypsi_aes_192_gcm_encrypt(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error);

// AES 192 GCM decrypt
int mcrypsi_aes_192_gcm_decrypt_init(UDF_INIT* initid, UDF_ARGS* args, char* message);
void mcrypsi_aes_192_gcm_decrypt_deinit(UDF_INIT* initid);
char* mcrypsi_aes_192_gcm_decrypt(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error);

// AES 256 GCM encrypt
int mcrypsi_aes_256_gcm_encrypt_init(UDF_INIT* initid, UDF_ARGS* args, char* message);
void mcrypsi_aes_256_gcm_encrypt_deinit(UDF_INIT* initid);
char* mcrypsi_aes_256_gcm_encrypt(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error);

// AES 256 GCM decrypt
int mcrypsi_aes_256_gcm_decrypt_init(UDF_INIT* initid, UDF_ARGS* args, char* message);
void mcrypsi_aes_256_gcm_decrypt_deinit(UDF_INIT* initid);
char* mcrypsi_aes_256_gcm_decrypt(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error);

// HMAC MD5
int mcrypsi_hmac_md5_init(UDF_INIT* initid, UDF_ARGS* args, char* message);
void mcrypsi_hmac_md5_deinit(UDF_INIT* initid);
char* mcrypsi_hmac_md5(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error);

// HMAC SHA1
int mcrypsi_hmac_sha1_init(UDF_INIT* initid, UDF_ARGS* args, char* message);
void mcrypsi_hmac_sha1_deinit(UDF_INIT* initid);
char* mcrypsi_hmac_sha1(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error);

// HMAC SHA256
int mcrypsi_hmac_sha256_init(UDF_INIT* initid, UDF_ARGS* args, char* message);
void mcrypsi_hmac_sha256_deinit(UDF_INIT* initid);
char* mcrypsi_hmac_sha256(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error);

// HMAC SHA384
int mcrypsi_hmac_sha384_init(UDF_INIT* initid, UDF_ARGS* args, char* message);
void mcrypsi_hmac_sha384_deinit(UDF_INIT* initid);
char* mcrypsi_hmac_sha384(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error);

// HMAC SHA512
int mcrypsi_hmac_sha512_init(UDF_INIT* initid, UDF_ARGS* args, char* message);
void mcrypsi_hmac_sha512_deinit(UDF_INIT* initid);
char* mcrypsi_hmac_sha512(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error);

// utilities
int validate_args(UDF_ARGS* args, char* function_name, char* message);

#ifdef __cplusplus
}
#endif

// utilities
int validate_args(UDF_ARGS* args, char* function_name, char* message) {
    if (args->arg_count != 2) {
        strcpy(message, function_name);
        strcat(message, " requires key and text parameters");
        return 1;
    }

    if (args->arg_type[0] != STRING_RESULT || args->arg_type[1] != STRING_RESULT) {
        strcpy(message, function_name);
        strcat(message, " requires key string and text string parameters");
        return 1;
    }

    if (args->lengths[0] <= 0 || args->lengths[1] <= 0) {
        strcpy(message, function_name);
        strcat(message, " parameters length value cannot less than 0");
        return 1;
    }

    return 0;
}

// AES 128 GCM encrypt
int mcrypsi_aes_128_gcm_encrypt_init(UDF_INIT* initid, UDF_ARGS* args, char* message) {
    char function_name[28] = "mcrypsi_aes_128_gcm_encrypt";
    function_name[28-1] = 0x0;

    if (validate_args(args, function_name, message) != 0) {
        return 1;
    }

    unsigned char* dst = NULL;

    initid->ptr = (char*) dst;

    return 0;
}

void mcrypsi_aes_128_gcm_encrypt_deinit(UDF_INIT* initid) {
    if (initid->ptr != NULL) {
        free((void*) initid->ptr);
    }
}

char* mcrypsi_aes_128_gcm_encrypt(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error) {
    unsigned char* dst = (unsigned char*) initid->ptr;
    int ret = 0;
    *length = 0;
    *is_null = 0;
    *error = 0;
    char* input_key = args->args[0];
    char* input_text = args->args[1];
    int text_size = args->lengths[1];

    int dst_size = 0;
    ret = crypsi_aes_128_gcm_encrypt(input_key, input_text, text_size, &dst, &dst_size);
    if (ret != 0) {
        *is_null = 1;
        *error = 1;
        return NULL;
    }

    *length = dst_size;
    memcpy(result, dst, dst_size);

    return result;
}

// AES 128 GCM decrypt
int mcrypsi_aes_128_gcm_decrypt_init(UDF_INIT* initid, UDF_ARGS* args, char* message) {
    char function_name[28] = "mcrypsi_aes_128_gcm_decrypt";
    function_name[28-1] = 0x0;

    if (validate_args(args, function_name, message) != 0) {
        return 1;
    }

    unsigned char* dst = NULL;

    initid->ptr = (char*) dst;

    return 0;
}

void mcrypsi_aes_128_gcm_decrypt_deinit(UDF_INIT* initid) {
    if (initid->ptr != NULL) {
        free((void*) initid->ptr);
    }
}

char* mcrypsi_aes_128_gcm_decrypt(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error) {
    unsigned char* dst = (unsigned char*) initid->ptr;
    int ret = 0;
    *length = 0;
    *is_null = 0;
    *error = 0;
    char* input_key = args->args[0];
    char* input_text = args->args[1];
    int text_size = args->lengths[1];

    int dst_size = 0;
    ret = crypsi_aes_128_gcm_decrypt(input_key, input_text, text_size, &dst, &dst_size);
    if (ret != 0) {
        *is_null = 1;
        *error = 1;
        return NULL;
    }

    *length = dst_size;
    memcpy(result, dst, dst_size);

    return result;
}

// AES 192 GCM encrypt
int mcrypsi_aes_192_gcm_encrypt_init(UDF_INIT* initid, UDF_ARGS* args, char* message) {
    char function_name[28] = "mcrypsi_aes_192_gcm_encrypt";
    function_name[28-1] = 0x0;

    if (validate_args(args, function_name, message) != 0) {
        return 1;
    }

    unsigned char* dst = NULL;

    initid->ptr = (char*) dst;

    return 0;
}

void mcrypsi_aes_192_gcm_encrypt_deinit(UDF_INIT* initid) {
    if (initid->ptr != NULL) {
        free((void*) initid->ptr);
    }
}

char* mcrypsi_aes_192_gcm_encrypt(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error) {
    unsigned char* dst = (unsigned char*) initid->ptr;
    int ret = 0;
    *length = 0;
    *is_null = 0;
    *error = 0;
    char* input_key = args->args[0];
    char* input_text = args->args[1];
    int text_size = args->lengths[1];

    int dst_size = 0;
    ret = crypsi_aes_192_gcm_encrypt(input_key, input_text, text_size, &dst, &dst_size);
    if (ret != 0) {
        *is_null = 1;
        *error = 1;
        return NULL;
    }

    *length = dst_size;
    memcpy(result, dst, dst_size);

    return result;
}

// AES 192 GCM decrypt
int mcrypsi_aes_192_gcm_decrypt_init(UDF_INIT* initid, UDF_ARGS* args, char* message) {
    char function_name[28] = "mcrypsi_aes_192_gcm_decrypt";
    function_name[28-1] = 0x0;

    if (validate_args(args, function_name, message) != 0) {
        return 1;
    }

    unsigned char* dst = NULL;

    initid->ptr = (char*) dst;

    return 0;
}

void mcrypsi_aes_192_gcm_decrypt_deinit(UDF_INIT* initid) {
    if (initid->ptr != NULL) {
        free((void*) initid->ptr);
    }
}

char* mcrypsi_aes_192_gcm_decrypt(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error) {
    unsigned char* dst = (unsigned char*) initid->ptr;
    int ret = 0;
    *length = 0;
    *is_null = 0;
    *error = 0;
    char* input_key = args->args[0];
    char* input_text = args->args[1];
    int text_size = args->lengths[1];

    int dst_size = 0;
    ret = crypsi_aes_192_gcm_decrypt(input_key, input_text, text_size, &dst, &dst_size);
    if (ret != 0) {
        *is_null = 1;
        *error = 1;
        return NULL;
    }

    *length = dst_size;
    memcpy(result, dst, dst_size);

    return result;
}

// AES 256 GCM encrypt
int mcrypsi_aes_256_gcm_encrypt_init(UDF_INIT* initid, UDF_ARGS* args, char* message) {
    char function_name[28] = "mcrypsi_aes_256_gcm_encrypt";
    function_name[28-1] = 0x0;

    if (validate_args(args, function_name, message) != 0) {
        return 1;
    }

    unsigned char* dst = NULL;

    initid->ptr = (char*) dst;

    return 0;
}

void mcrypsi_aes_256_gcm_encrypt_deinit(UDF_INIT* initid) {
    if (initid->ptr != NULL) {
        free((void*) initid->ptr);
    }
}

char* mcrypsi_aes_256_gcm_encrypt(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error) {
    unsigned char* dst = (unsigned char*) initid->ptr;
    int ret = 0;
    *length = 0;
    *is_null = 0;
    *error = 0;
    char* input_key = args->args[0];
    char* input_text = args->args[1];
    int text_size = args->lengths[1];

    int dst_size = 0;
    ret = crypsi_aes_256_gcm_encrypt(input_key, input_text, text_size, &dst, &dst_size);
    if (ret != 0) {
        *is_null = 1;
        *error = 1;
        return NULL;
    }

    *length = dst_size;
    memcpy(result, dst, dst_size);

    return result;
}

// AES 256 GCM decrypt
int mcrypsi_aes_256_gcm_decrypt_init(UDF_INIT* initid, UDF_ARGS* args, char* message) {
    char function_name[28] = "mcrypsi_aes_256_gcm_decrypt";
    function_name[28-1] = 0x0;

    if (validate_args(args, function_name, message) != 0) {
        return 1;
    }

    unsigned char* dst = NULL;

    initid->ptr = (char*) dst;

    return 0;
}

void mcrypsi_aes_256_gcm_decrypt_deinit(UDF_INIT* initid) {
    if (initid->ptr != NULL) {
        free((void*) initid->ptr);
    }
}

char* mcrypsi_aes_256_gcm_decrypt(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error) {
    unsigned char* dst = (unsigned char*) initid->ptr;
    int ret = 0;
    *length = 0;
    *is_null = 0;
    *error = 0;
    char* input_key = args->args[0];
    char* input_text = args->args[1];
    int text_size = args->lengths[1];

    int dst_size = 0;
    ret = crypsi_aes_256_gcm_decrypt(input_key, input_text, text_size, &dst, &dst_size);
    if (ret != 0) {
        *is_null = 1;
        *error = 1;
        return NULL;
    }

    *length = dst_size;
    memcpy(result, dst, dst_size);

    return result;
}

// HMAC MD5
int mcrypsi_hmac_md5_init(UDF_INIT* initid, UDF_ARGS* args, char* message) {
    char function_name[17] = "mcrypsi_hmac_md5";
    function_name[17-1] = 0x0;

    if (validate_args(args, function_name, message) != 0) {
        return 1;
    }

    unsigned char* dst = NULL;

    initid->ptr = (char*) dst;

    return 0;
}

void mcrypsi_hmac_md5_deinit(UDF_INIT* initid) {
    if (initid->ptr != NULL) {
        free((void*) initid->ptr);
    }
}

char* mcrypsi_hmac_md5(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error) {
    unsigned char* dst = (unsigned char*) initid->ptr;
    int ret = 0;
    *length = 0;
    *is_null = 0;
    *error = 0;
    char* input_key = args->args[0];
    char* input_text = args->args[1];
    int text_size = args->lengths[1];

    int dst_size = 0;
    ret = crypsi_hmac_md5(input_key, input_text, text_size, &dst, &dst_size);
    if (ret != 0) {
        *is_null = 1;
        *error = 1;
        return NULL;
    }

    *length = dst_size;
    memcpy(result, dst, dst_size);

    return result;
}

// HMAC SHA1
int mcrypsi_hmac_sha1_init(UDF_INIT* initid, UDF_ARGS* args, char* message) {
    char function_name[18] = "mcrypsi_hmac_sha1";
    function_name[18-1] = 0x0;

    if (validate_args(args, function_name, message) != 0) {
        return 1;
    }

    unsigned char* dst = NULL;

    initid->ptr = (char*) dst;

    return 0;
}

void mcrypsi_hmac_sha1_deinit(UDF_INIT* initid) {
    if (initid->ptr != NULL) {
        free((void*) initid->ptr);
    }
}

char* mcrypsi_hmac_sha1(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error) {
    unsigned char* dst = (unsigned char*) initid->ptr;
    int ret = 0;
    *length = 0;
    *is_null = 0;
    *error = 0;
    char* input_key = args->args[0];
    char* input_text = args->args[1];
    int text_size = args->lengths[1];

    int dst_size = 0;
    ret = crypsi_hmac_sha1(input_key, input_text, text_size, &dst, &dst_size);
    if (ret != 0) {
        *is_null = 1;
        *error = 1;
        return NULL;
    }

    *length = dst_size;
    memcpy(result, dst, dst_size);

    return result;
}

// HMAC SHA256
int mcrypsi_hmac_sha256_init(UDF_INIT* initid, UDF_ARGS* args, char* message) {
    char function_name[20] = "mcrypsi_hmac_sha256";
    function_name[20-1] = 0x0;

    if (validate_args(args, function_name, message) != 0) {
        return 1;
    }

    unsigned char* dst = NULL;

    initid->ptr = (char*) dst;

    return 0;
}

void mcrypsi_hmac_sha256_deinit(UDF_INIT* initid) {
    if (initid->ptr != NULL) {
        free((void*) initid->ptr);
    }
}

char* mcrypsi_hmac_sha256(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error) {
    unsigned char* dst = (unsigned char*) initid->ptr;
    int ret = 0;
    *length = 0;
    *is_null = 0;
    *error = 0;
    char* input_key = args->args[0];
    char* input_text = args->args[1];
    int text_size = args->lengths[1];

    int dst_size = 0;
    ret = crypsi_hmac_sha256(input_key, input_text, text_size, &dst, &dst_size);
    if (ret != 0) {
        *is_null = 1;
        *error = 1;
        return NULL;
    }

    *length = dst_size;
    memcpy(result, dst, dst_size);

    return result;
}

// HMAC SHA384
int mcrypsi_hmac_sha384_init(UDF_INIT* initid, UDF_ARGS* args, char* message) {
    char function_name[20] = "mcrypsi_hmac_sha384";
    function_name[20-1] = 0x0;

    if (validate_args(args, function_name, message) != 0) {
        return 1;
    }

    unsigned char* dst = NULL;

    initid->ptr = (char*) dst;

    return 0;
}

void mcrypsi_hmac_sha384_deinit(UDF_INIT* initid) {
    if (initid->ptr != NULL) {
        free((void*) initid->ptr);
    }
}

char* mcrypsi_hmac_sha384(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error) {
    unsigned char* dst = (unsigned char*) initid->ptr;
    int ret = 0;
    *length = 0;
    *is_null = 0;
    *error = 0;
    char* input_key = args->args[0];
    char* input_text = args->args[1];
    int text_size = args->lengths[1];

    int dst_size = 0;
    ret = crypsi_hmac_sha384(input_key, input_text, text_size, &dst, &dst_size);
    if (ret != 0) {
        *is_null = 1;
        *error = 1;
        return NULL;
    }

    *length = dst_size;
    memcpy(result, dst, dst_size);

    return result;
}

// HMAC SHA512
int mcrypsi_hmac_sha512_init(UDF_INIT* initid, UDF_ARGS* args, char* message) {
    char function_name[20] = "mcrypsi_hmac_sha512";
    function_name[20-1] = 0x0;

    if (validate_args(args, function_name, message) != 0) {
        return 1;
    }

    unsigned char* dst = NULL;

    initid->ptr = (char*) dst;

    return 0;
}

void mcrypsi_hmac_sha512_deinit(UDF_INIT* initid) {
    if (initid->ptr != NULL) {
        free((void*) initid->ptr);
    }
}

char* mcrypsi_hmac_sha512(UDF_INIT* initid, UDF_ARGS* args, char* result, 
    unsigned long* length, char* is_null, char* error) {
    unsigned char* dst = (unsigned char*) initid->ptr;
    int ret = 0;
    *length = 0;
    *is_null = 0;
    *error = 0;
    char* input_key = args->args[0];
    char* input_text = args->args[1];
    int text_size = args->lengths[1];

    int dst_size = 0;
    ret = crypsi_hmac_sha512(input_key, input_text, text_size, &dst, &dst_size);
    if (ret != 0) {
        *is_null = 1;
        *error = 1;
        return NULL;
    }

    *length = dst_size;
    memcpy(result, dst, dst_size);

    return result;
}