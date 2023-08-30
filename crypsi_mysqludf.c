#include <mysql.h>
#include <string.h>
#include "crypsi.h"

#ifdef __cplusplus
extern "C" {
#endif

// AES 128 GCM encrypt
my_bool mcrypsi_aes_128_gcm_encrypt_init(UDF_INIT* initid, UDF_ARGS* args, char* message);
void mcrypsi_aes_128_gcm_encrypt_deinit(UDF_INIT* initid);
char* mcrypsi_aes_128_gcm_encrypt(UDF_INIT* initid, UDF_ARGS* args, char* result, unsigned long* length, char* is_null, char* error);

// AES 128 GCM decrypt
my_bool mcrypsi_aes_128_gcm_decrypt_init(UDF_INIT* initid, UDF_ARGS* args, char* message);
void mcrypsi_aes_128_gcm_decrypt_deinit(UDF_INIT* initid);
char* mcrypsi_aes_128_gcm_decrypt(UDF_INIT* initid, UDF_ARGS* args, char* result, unsigned long* length, char* is_null, char* error);

// utilities
my_bool validate_args(UDF_ARGS* args, char* function_name, char* message);

#ifdef __cplusplus
}
#endif

// utilities
my_bool validate_args(UDF_ARGS* args, char* function_name, char* message) {
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
my_bool mcrypsi_aes_128_gcm_encrypt_init(UDF_INIT* initid, UDF_ARGS* args, char* message) {
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

char* mcrypsi_aes_128_gcm_encrypt(UDF_INIT* initid, UDF_ARGS* args, char* result, unsigned long* length, char* is_null, char* error) {
    unsigned char* dst = (unsigned char*) initid->ptr;
    int ret = 0;
    char* input_key = args->args[0];
    char* input_text = args->args[1];
    int text_size = args->lengths[1];

    int dst_size = 0;
    ret = crypsi_aes_128_gcm_encrypt(input_key, input_text, text_size, &dst, &dst_size);
    if (ret != 0) {
        strcpy(error, "error encrypt with crypsi_aes_128_gcm_encrypt");
		*is_null = 1;
		return NULL;
    }

    *length = dst_size;
    memcpy(result, dst, dst_size);

    return result;
}

// AES 128 GCM decrypt
my_bool mcrypsi_aes_128_gcm_decrypt_init(UDF_INIT* initid, UDF_ARGS* args, char* message) {
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

char* mcrypsi_aes_128_gcm_decrypt(UDF_INIT* initid, UDF_ARGS* args, char* result, unsigned long* length, char* is_null, char* error) {
    unsigned char* dst = (unsigned char*) initid->ptr;
    int ret = 0;
    char* input_key = args->args[0];
    char* input_text = args->args[1];
    int text_size = args->lengths[1];

    int dst_size = 0;
    ret = crypsi_aes_128_gcm_decrypt(input_key, input_text, text_size, &dst, &dst_size);
    if (ret != 0) {
        strcpy(error, "error encrypt with mcrypsi_aes_128_gcm_decrypt");
		*is_null = 1;
		return NULL;
    }

    *length = dst_size;
    memcpy(result, dst, dst_size);

    return result;
}