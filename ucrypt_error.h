/*
 * in this file we will define error classes and error codes 
 * first general error such as error produced in parsing arguments,header generation,encryption,decryption etc. from (1-20)
 * and then will follow more specific codes from (21--onwards)
 */
#ifndef __UCRYPT_ERROR_H__
#define __UCRYPT_ERROR_H__
#include "ucrypt_common.h"
/*
 * following variables allows us to change standard program output behaviour 
 */
#define UCRYPT_STDOUT stdout
#define UCRYPT_STDERR stderr
#define UCRYPT_STDIN stdin
/*
 * set UCRYPT_DEBUG to TRUE or FALSE depending upon the level of verbosity required
 * UCRYPT_DEBUG TRUE when everything including internal debugging messages to written to
 */
#define UCRYPT_DEBUG TRUE

#define UCRYPT_ERR_STRING_LEN 200

/*first error classes*/
#define UCRYPT_OK 0

typedef enum{UCRYPT_ERR_INVALID_ARGS=1,UCRYPT_ERR_INVALID_COMMAND,
			UCRYPT_ERR_FILE_CREATE,UCRYPT_ERR_FILE_OPEN,
			UCRYPT_ERR_FILE_READ,UCRYPT_ERR_FILE_WRITE,
			UCRYPT_ERR_IV_GEN,UCRYPT_ERR_KEY_GEN,
			UCRYPT_ERR_HEADER_GEN,UCRYPT_ERR_HEADER_READ,
			UCRYPT_ERR_VERSION_INCOMPAT,UCRYPT_ERR_CRYPT,
			UCRYPT_ERR_DCRYPT,UCRYPT_ERR_ATTR_LOAD,
			UCRYPT_ERR_HMAC_ATTACH,UCRYPT_ERR_HMAC_VERIFY,
			UCRYPT_ERR_PASSWD_READ,UCRYPT_ERR} error_codes_t;
/*error structure*/
typedef struct {
    /*unsigned int class;*/
    short int err_code;
    char err_string[UCRYPT_ERR_STRING_LEN];
    
}ucrypt_error_table;
void ucrypt_log_error();


#endif

