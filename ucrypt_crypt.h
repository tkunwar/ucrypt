/*
 * ucrypt_crypt.h
 * 
 */
#ifndef __UCRYPT_H__
#define __UCRYPT_H__

#include "ucrypt_common.h"
#include "ucrypt_version.h"
/*the basic header --will be used to detect if a file is an ucrypt encrypted file **/
typedef struct{
    char ucrypt[3];
    unsigned char version;
    /*
   unsigned char version_minor;
    unsigned char last_block_size;*/
}ucrypt_header;

/*
 * structure to store arguments for action encrypt
 * must be provided if action is to encrypt
 */

struct UCRYPT_ARGS{
		char src_file[FILE_PATH_LEN ];
	    char out_file[FILE_PATH_LEN ];
	    unsigned char iv[MAX_IV_LEN];
	    unsigned char key[MAX_KEY_LEN];
	    char passphrase[MAX_PASSPHRASE_LEN];
	    _uint16 iv_len;
	    _uint16 pass_len;
	    _uint16 key_len;
	    UCRYPT_BOOL args_ok;
	    crypt_algo_t crypt_algo;
}ucrypt_args;


//do we need this extension header ?
typedef struct {
    char prog_name[PROG_NAME_LEN];
    char ver_string[VERSION_STR_LEN];
    char crypt_algo[CRYPT_ALGO_LEN];
    char iv[MAX_IV_LEN];
}extension_header;

#define EXTENSION_BUFF_LEN 0xff

UCRYPT_BOOL process_args(int, char**);
void print_usage();
void print_version();
void init_ecrypt_args();
UCRYPT_BOOL check_if_ecrypt_args_populated();
void dump_args();
UCRYPT_BOOL generate_header_old(FILE *outfp);
void print_extension_header(extension_header exthdr);

UCRYPT_BOOL generate_header(FILE *outfp);
UCRYPT_BOOL analyze_header(FILE *infp, extension_header *exhdr);
UCRYPT_BOOL encrypt_main(FILE *infp, FILE *outfp);
UCRYPT_BOOL decrypt_main(FILE *infp, FILE *outfp);
void cleanup(const char *src_file);

#endif

