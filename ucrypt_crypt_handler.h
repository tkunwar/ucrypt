/* 
 * File:   ucrypt_crypt_handler.h
 *
 * Created on February 4, 2012, 5:22 PM
 */

#ifndef UCRYPT_CRYPT_HANDLER_H
#define UCRYPT_CRYPT_HANDLER_H

#ifdef	__cplusplus
extern "C" {
#endif
#include "ucrypt_common.h"

/* this structure will contain parametres what we will recieve
 */
typedef struct {
	crypt_algo_t crypt_algo;
	unsigned char key[MAX_KEY_LEN];
	_uint16 key_len;
	unsigned char iv[MAX_IV_LEN];
	_uint16 iv_len;
} crypt_handler_state;

//init the crypt_handler_state
void crypt_handler_init(crypt_handler_state *s,
		crypt_algo_t crypt_algo, const unsigned char *key, _uint16 key_len,
		const unsigned char *iv, _uint16 iv_len);

UCRYPT_ERR crypt_handler_encrypt(crypt_handler_state *s, FILE *infp,
		FILE *outfp);

UCRYPT_ERR crypt_handler_decrypt(crypt_handler_state *s, FILE *infp,
		FILE *outfp);
_uint64 crypt_handler_get_payload_info(FILE *infp, _uint64 *file_size);
UCRYPT_ERR crypt_handler_attach_hmac(FILE *outfp, const _uchar* hmac,
		_uint16 hmac_len);
UCRYPT_ERR crypt_handler_verify_hmac(FILE *infp, const _uchar* hmac,
		_uint16 hmac_len);
#ifdef	__cplusplus
}
#endif

#endif	/* UCRYPT_CRYPT_HANDLER_H */

