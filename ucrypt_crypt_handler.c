#include "ucrypt_crypt_handler.h"

/*
 * @@crypt_handler_init()
 * Description: intialize the crypt_handler_state.
 */
void crypt_handler_init(crypt_handler_state *state, crypt_algo_t crypt_algo,
		const unsigned char *key, _uint16 key_len, const unsigned char *iv,
		_uint16 iv_len) {
	memcpy(state->iv, iv, iv_len);
	memcpy(state->key, key, key_len);
	state->crypt_algo = crypt_algo;
	state->iv_len = iv_len;
	state->key_len = key_len;
}

/*
 * @@crypt_handler_encrypt()
 * Description: actual encryption routine. Utilizes library rotuines to encrypt
 * 				the input stream specified by infp to outfp.
 */UCRYPT_ERR crypt_handler_encrypt(crypt_handler_state *state, FILE *infp,
		FILE *outfp) {
	unsigned char pt_buffer[CRYPT_BUFF_SIZE];
	unsigned char ct_buffer[CRYPT_BUFF_SIZE];
	unsigned char buff[MAX_ATTR_LEN_SIZE];
	unsigned char hmac_buff[HMAC_BUFF_SIZE];
	hmac_state hmac;
	_int16 lib_error;
	symmetric_CTR ctr;
	_uint64 file_size = get_file_size(infp);
	_int16 bytes_read = -1;
	_uint64 bytes_encrypted = 0;
	_uint32 hmac_len;

	switch (state->crypt_algo) {
	case BLOWFISH:
		if (register_cipher(&blowfish_desc) == -1) {
			serror("Failed to register AES");
			return UCRYPT_ERR_CRYPT;
		}
		if ((lib_error = ctr_start(find_cipher("blowfish"), state->iv,
				state->key, state->key_len, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr))
				!= CRYPT_OK) {
			var_error("ctr_start error: %s\n", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}

		memset(buff, 0, MAX_ATTR_LEN_SIZE);
		store16(buff, ATTR_PAYLOAD);

		if (fwrite(buff, 1, ATTR_CODE_SIZE, outfp) != ATTR_CODE_SIZE) {
			serror("Failed to write frame markers.");
			return UCRYPT_ERR_CRYPT;
		}
		memset(buff, 0, MAX_ATTR_LEN_SIZE);
		store64(buff, file_size);
		if (fwrite(buff, 1, MAX_PAYLOAD_SIZE, outfp) != MAX_PAYLOAD_SIZE) {
			serror("Failed to write frame markers.");
			return UCRYPT_ERR_CRYPT;
		}

		if (register_hash(&sha256_desc) == -1) {
			serror("Error registering SHA256");
			return UCRYPT_ERR_CRYPT;
		}
		if ((lib_error = hmac_init(&hmac, find_hash("sha256"), state->key,
				state->key_len)) != CRYPT_OK) {
			var_error("Error setting up hmac: %s", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}

		while ((bytes_read = fread(pt_buffer, 1, CRYPT_BUFF_SIZE, infp)) > 0) {
			if ((lib_error = ctr_encrypt(pt_buffer, ct_buffer, bytes_read, &ctr))
					!= CRYPT_OK) {
				var_error("ctr_encrypt error: %s\n",
						error_to_string(lib_error));
				return UCRYPT_ERR_CRYPT;
			}
			if ((lib_error = hmac_process(&hmac, ct_buffer, bytes_read))
					!= CRYPT_OK) {
				var_error("Error processing hmac : %s",
						error_to_string(lib_error));
				return UCRYPT_ERR_CRYPT;
			}
			if (fwrite(ct_buffer, 1, bytes_read, outfp) != bytes_read) {
				serror("Failed to write output stream ");
				return UCRYPT_ERR_CRYPT;
			}
			bytes_encrypted += bytes_read;
			if (bytes_encrypted == file_size)
				break;
		}
		if (bytes_read < 0) {
			serror("Could not complete encryption");
			return UCRYPT_ERR_CRYPT;
		}
		hmac_len = sizeof(hmac_buff);
		if ((lib_error = hmac_done(&hmac, hmac_buff, &hmac_len)) != CRYPT_OK) {
			var_error("Error finishing hmac : %s", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}
		if (crypt_handler_attach_hmac(outfp, hmac_buff, hmac_len) != UCRYPT_OK) {
			serror("Failed to save HMAC");
			return UCRYPT_ERR_CRYPT;
		}
		if ((lib_error = ctr_done(&ctr)) != CRYPT_OK) {
			var_error("ctr_done error: %s", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}
		zeromem(&ctr, sizeof(ctr));
		break;
	case CAST:
		if (register_cipher(&cast5_desc) == -1) {
			serror("Failed to register CAST");
			return UCRYPT_ERR_CRYPT;
		}
		if ((lib_error = ctr_start(find_cipher("cast5"), state->iv, state->key,
				state->key_len, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr))
				!= CRYPT_OK) {
			var_error("ctr_start error: %s\n", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}

		memset(buff, 0, MAX_ATTR_LEN_SIZE);
		store16(buff, ATTR_PAYLOAD);
		if (fwrite(buff, 1, ATTR_CODE_SIZE, outfp) != ATTR_CODE_SIZE) {
			serror("Failed to write frame markers.");
			return UCRYPT_ERR_CRYPT;
		}
		memset(buff, 0, MAX_ATTR_LEN_SIZE);
		store64(buff, file_size);
		if (fwrite(buff, 1, MAX_PAYLOAD_SIZE, outfp) != MAX_PAYLOAD_SIZE) {
			serror("Failed to write frame markers.");
			return UCRYPT_ERR_CRYPT;
		}
		if (register_hash(&sha256_desc) == -1) {
			serror("Error registering SHA256");
			return UCRYPT_ERR_CRYPT;
		}
		if ((lib_error = hmac_init(&hmac, find_hash("sha256"), state->key,
				state->key_len)) != CRYPT_OK) {
			var_error("Error setting up hmac: %s", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}

		while ((bytes_read = fread(pt_buffer, 1, CRYPT_BUFF_SIZE, infp)) > 0) {
			if ((lib_error = ctr_encrypt(pt_buffer, ct_buffer, bytes_read, &ctr))
					!= CRYPT_OK) {
				var_error("ctr_encrypt error: %s\n",
						error_to_string(lib_error));
				return UCRYPT_ERR_CRYPT;
			}
			if ((lib_error = hmac_process(&hmac, ct_buffer, bytes_read))
					!= CRYPT_OK) {
				var_error("Error processing hmac : %s",
						error_to_string(lib_error));
				return UCRYPT_ERR_CRYPT;
			}
			if (fwrite(ct_buffer, 1, bytes_read, outfp) != bytes_read) {
				serror("Could write to output stream");
				return UCRYPT_ERR_CRYPT;
			}
			bytes_encrypted += bytes_read;
			if (bytes_encrypted == file_size)
				break;
		}
		if (bytes_read < 0) {
			serror("Could not complete encryption");
			return UCRYPT_ERR_CRYPT;
		}
		hmac_len = sizeof(hmac_buff);
		if ((lib_error = hmac_done(&hmac, hmac_buff, &hmac_len)) != CRYPT_OK) {
			var_error("\nError finishing hmac : %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}
		if (crypt_handler_attach_hmac(outfp, hmac_buff, hmac_len) != UCRYPT_OK) {
			serror("Failed to save HMAC");
			return UCRYPT_ERR_CRYPT;
		}
		if ((lib_error = ctr_done(&ctr)) != CRYPT_OK) {
			var_error("ctr_done error: %s", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}
		zeromem(&ctr, sizeof(ctr));
		break;
	case AES:
		if (register_cipher(&aes_desc) == -1) {
			serror("Failed to register AES");
			return UCRYPT_ERR_CRYPT;
		}
		if ((lib_error = ctr_start(find_cipher("aes"), state->iv, state->key,
				state->key_len, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr))
				!= CRYPT_OK) {
			var_error("ctr_start error: %s\n", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}

		memset(buff, 0, MAX_ATTR_LEN_SIZE);
		store16(buff, ATTR_PAYLOAD);
		if (fwrite(buff, 1, ATTR_CODE_SIZE, outfp) != ATTR_CODE_SIZE) {
			serror("Failed to write frame markers.");
			return UCRYPT_ERR_CRYPT;
		}
		memset(buff, 0, MAX_ATTR_LEN_SIZE);
		store64(buff, file_size);
		if (fwrite(buff, 1, MAX_PAYLOAD_SIZE, outfp) != MAX_PAYLOAD_SIZE) {
			serror("Failed to write frame markers.");
			return UCRYPT_ERR_CRYPT;
		}
		if (register_hash(&sha256_desc) == -1) {
			serror("Error registering SHA256");
			return UCRYPT_ERR_CRYPT;
		}
		if ((lib_error = hmac_init(&hmac, find_hash("sha256"), state->key,
				state->key_len)) != CRYPT_OK) {
			var_error("Error setting up hmac: %s", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}

		while ((bytes_read = fread(pt_buffer, 1, CRYPT_BUFF_SIZE, infp)) > 0) {
			if ((lib_error = ctr_encrypt(pt_buffer, ct_buffer, bytes_read, &ctr))
					!= CRYPT_OK) {
				var_error("ctr_encrypt error: %s\n",
						error_to_string(lib_error));
				return UCRYPT_ERR_CRYPT;
			}
			if ((lib_error = hmac_process(&hmac, ct_buffer, bytes_read))
					!= CRYPT_OK) {
				var_error( "Error processing hmac : %s",
						error_to_string(lib_error));
				return UCRYPT_ERR_CRYPT;
			}
			if (fwrite(ct_buffer, 1, bytes_read, outfp) != bytes_read) {
				serror("Failed to write to output stream");
				return UCRYPT_ERR_CRYPT;
			}
			bytes_encrypted += bytes_read;
			if (bytes_encrypted == file_size)
				break;
		}
		if (bytes_read < 0) {
			serror("Could not complete encryption");
			return UCRYPT_ERR_CRYPT;
		}
		hmac_len = sizeof(hmac_buff);
		if ((lib_error = hmac_done(&hmac, hmac_buff, &hmac_len)) != CRYPT_OK) {
			var_error("Error finishing hmac : %s", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}
		if (crypt_handler_attach_hmac(outfp, hmac_buff, hmac_len) != UCRYPT_OK) {
			serror("Failed to save HMAC");
			return UCRYPT_ERR_CRYPT;
		}
		if ((lib_error = ctr_done(&ctr)) != CRYPT_OK) {
			var_error("ctr_done error: %s", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}
		zeromem(&ctr, sizeof(ctr));
		break;
	default:
		break;
	} //end of switch
	return CRYPT_OK;
}

/*
 * @@crypt_handler_decrypt()
 * Description: actual routine to decrypt the stream infp and writes the
 * 				decrypted stream to the outfp.
 */
 UCRYPT_ERR crypt_handler_decrypt(crypt_handler_state *state, FILE *infp,
		FILE *outfp) {
	unsigned char pt_buffer[CRYPT_BUFF_SIZE];
	unsigned char ct_buffer[CRYPT_BUFF_SIZE];
	unsigned char hmac_buff[HMAC_BUFF_SIZE];
	hmac_state hmac;
	_int16 lib_error;
	symmetric_CTR ctr;
	_int16 bytes_read = -1;
	_uint32 hmac_len;
	_uint64 file_size = 0,  decrypted_bytes = 0,
			bytes_to_read = 0;
	rewind(infp);

	switch (state->crypt_algo) {
	case BLOWFISH:
		if (register_cipher(&blowfish_desc) == -1) {
			fprintf(UCRYPT_STDERR, "\nFailed to register AES");
			return UCRYPT_ERR_DCRYPT;
		}
		if ((lib_error = ctr_start(find_cipher("blowfish"), state->iv,
				state->key, state->key_len, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr))
				!= CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nctr_start error: %s\n",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}
		if ((lib_error = ctr_setiv(state->iv, state->iv_len, &ctr))
				!= CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nctr_setiv error: %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}
		if (register_hash(&sha256_desc) == -1) {
			fprintf(UCRYPT_STDERR, "\nError registering SHA256");
			return UCRYPT_ERR_DCRYPT;
		}
		if ((lib_error = hmac_init(&hmac, find_hash("sha256"), state->key,
				state->key_len)) != CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nError setting up hmac: %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}

		bytes_to_read =
				(CRYPT_BUFF_SIZE < file_size) ? CRYPT_BUFF_SIZE : file_size;
		while ((bytes_read = fread(ct_buffer, 1, bytes_to_read, infp)) > 0) {

			if ((lib_error = ctr_decrypt(ct_buffer, pt_buffer, bytes_read, &ctr))
					!= CRYPT_OK) {
				fprintf(UCRYPT_STDERR, "\nctr_decrypt error: %s\n",
						error_to_string(lib_error));
				return UCRYPT_ERR_DCRYPT;
			}
			if ((lib_error = hmac_process(&hmac, ct_buffer, bytes_read))
					!= CRYPT_OK) {
				fprintf(UCRYPT_STDERR, "\nError processing hmac : %s",
						error_to_string(lib_error));
				return UCRYPT_ERR_DCRYPT;
			}
			if (fwrite(pt_buffer, 1, bytes_read, outfp) != bytes_read) {
				serror("Failed to write decrypted block");
				return UCRYPT_ERR_DCRYPT;
			}

			decrypted_bytes += bytes_read;
			bytes_to_read = file_size - decrypted_bytes;
			bytes_to_read =
					(bytes_to_read >= CRYPT_BUFF_SIZE) ?
							CRYPT_BUFF_SIZE : bytes_to_read;
			if (decrypted_bytes == file_size)
				break;
		}
		if (bytes_read < 0) {
			serror("A read error occurred");
			return UCRYPT_ERR_DCRYPT;
		}
		hmac_len = sizeof(hmac_buff);
		if ((lib_error = hmac_done(&hmac, hmac_buff, &hmac_len)) != CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nError finishing hmac : %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}

		if (crypt_handler_verify_hmac(infp, hmac_buff, hmac_len) != CRYPT_OK) {
			serror("HMAC verification failed");
			return UCRYPT_ERR_HMAC_VERIFY;
		}
		if ((lib_error = ctr_done(&ctr)) != CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nctr_done error: %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}
		zeromem(&ctr, sizeof(ctr));
		break;
	case CAST:
		if (register_cipher(&cast5_desc) == -1) {
			fprintf(UCRYPT_STDERR, "\nFailed to register AES");
			return UCRYPT_ERR_DCRYPT;
		}
		if ((lib_error = ctr_start(find_cipher("cast5"), state->iv, state->key,
				state->key_len, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr))
				!= CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nctr_start error: %s\n",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}
		if ((lib_error = ctr_setiv(state->iv, state->iv_len, &ctr))
				!= CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nctr_setiv error: %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}
		if (register_hash(&sha256_desc) == -1) {
			fprintf(UCRYPT_STDERR, "\nError registering SHA256");
			return UCRYPT_ERR_DCRYPT;
		}
		if ((lib_error = hmac_init(&hmac, find_hash("sha256"), state->key,
				state->key_len)) != CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nError setting up hmac: %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}

		bytes_to_read =
				(CRYPT_BUFF_SIZE < file_size) ? CRYPT_BUFF_SIZE : file_size;
		while ((bytes_read = fread(ct_buffer, 1, CRYPT_BUFF_SIZE, infp)) > 0) {

			if ((lib_error = ctr_decrypt(ct_buffer, pt_buffer, bytes_read, &ctr))
					!= CRYPT_OK) {
				fprintf(UCRYPT_STDERR, "\nctr_decrypt error: %s\n",
						error_to_string(lib_error));
				return UCRYPT_ERR_DCRYPT;
			}
			if ((lib_error = hmac_process(&hmac, ct_buffer, bytes_read))
					!= CRYPT_OK) {
				fprintf(UCRYPT_STDERR, "\nError processing hmac : %s",
						error_to_string(lib_error));
				return UCRYPT_ERR_DCRYPT;
			}
			if (fwrite(pt_buffer, 1, bytes_read, outfp) != bytes_read) {
				serror("Failed to write decrypted block");
				return UCRYPT_ERR_FILE_WRITE;
			}
			decrypted_bytes += bytes_read;
			bytes_to_read = file_size - decrypted_bytes;
			bytes_to_read =
					(bytes_to_read >= CRYPT_BUFF_SIZE) ?
							CRYPT_BUFF_SIZE : bytes_to_read;
			if (decrypted_bytes == file_size)
				break;
		}
		if (bytes_read < 0) {
			serror("A read error occurred");
			return UCRYPT_ERR_FILE_READ;
		}

		hmac_len = sizeof(hmac_buff);
		if ((lib_error = hmac_done(&hmac, hmac_buff, &hmac_len)) != CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nError finishing hmac : %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}

		if (crypt_handler_verify_hmac(infp, hmac_buff, hmac_len) != CRYPT_OK) {
			serror("HMAC verification failed");
			return UCRYPT_ERR_HMAC_VERIFY;
		}
		if ((lib_error = ctr_done(&ctr)) != CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nctr_done error: %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}
		zeromem(&ctr, sizeof(ctr));
		break;
	case AES:
		if (register_cipher(&aes_desc) == -1) {
			fprintf(UCRYPT_STDERR, "\nFailed to register AES");
			return UCRYPT_ERR_DCRYPT;
		}
		if ((lib_error = ctr_start(find_cipher("aes"), state->iv, state->key,
				state->key_len, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr))
				!= CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nctr_start error: %s\n",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}

		if ((lib_error = ctr_setiv(state->iv, state->iv_len, &ctr))
				!= CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nctr_setiv error: %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}
		if (register_hash(&sha256_desc) == -1) {
			fprintf(UCRYPT_STDERR, "\nError registering SHA256");
			return UCRYPT_ERR_DCRYPT;
		}
		if ((lib_error = hmac_init(&hmac, find_hash("sha256"), state->key,
				state->key_len)) != CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nError setting up hmac: %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}
		bytes_to_read =
				(CRYPT_BUFF_SIZE < file_size) ? CRYPT_BUFF_SIZE : file_size;
		while ((bytes_read = fread(ct_buffer, 1, bytes_to_read, infp)) > 0) {
			if ((lib_error = ctr_decrypt(ct_buffer, pt_buffer, bytes_read, &ctr))
					!= CRYPT_OK) {
				fprintf(UCRYPT_STDERR, "\nctr_decrypt error: %s\n",
						error_to_string(lib_error));
				return UCRYPT_ERR_DCRYPT;
			}
			if ((lib_error = hmac_process(&hmac, ct_buffer, bytes_read))
					!= CRYPT_OK) {
				fprintf(UCRYPT_STDERR, "\nError processing hmac : %s",
						error_to_string(lib_error));
				return UCRYPT_ERR_DCRYPT;
			}
			if (fwrite(pt_buffer, 1, bytes_read, outfp) != bytes_read) {
				serror("Failed to write decrypted block");
				return UCRYPT_ERR_FILE_WRITE;
			}

			decrypted_bytes += bytes_read;
			bytes_to_read = file_size - decrypted_bytes;
			bytes_to_read =
					(bytes_to_read >= CRYPT_BUFF_SIZE) ?
							CRYPT_BUFF_SIZE : bytes_to_read;
			if (decrypted_bytes == file_size) {
				var_debug("Wrote %llu bytes", decrypted_bytes);
				break;
			}

		}
		if (bytes_read < 0) {
			serror("A read error occurred");
			return UCRYPT_ERR_FILE_READ;
		}
		hmac_len = sizeof(hmac_buff);
		if ((lib_error = hmac_done(&hmac, hmac_buff, &hmac_len)) != CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nError finishing hmac : %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}

		if (crypt_handler_verify_hmac(infp, hmac_buff, hmac_len) != CRYPT_OK) {
			serror("HMAC verification failed");
			return UCRYPT_ERR_HMAC_VERIFY;
		}

		if ((lib_error = ctr_done(&ctr)) != CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nctr_done error: %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}
		zeromem(&ctr, sizeof(ctr));
		break;
	default:
		serror("Unsupported algorithm");
		return UCRYPT_ERR_DCRYPT;
		break;
	}
	return UCRYPT_OK;
}

/*
 * @@crypt_handler_get_payload_info()
 * Description:this routine will return payload_begin_pos in two ways:
 * 				first return the position of payload from begining of file
 * 				in bytes. also the infp will be moved to that position
 * 				accurately. it's upon the caller to decide which one to choose.
 */
_uint64 crypt_handler_get_payload_info(FILE *infp, _uint64 *file_size) {
	_uint64 payload_start_pos = 0;
	_uint16 attrib_code, attrib_len;
	 _uchar buff[MAX_ATTR_LEN_SIZE];
	rewind(infp);
	while (infp) {
		memset(buff, 0, MAX_ATTR_LEN_SIZE);
		if (fread(buff, 1, ATTR_CODE_SIZE, infp) != ATTR_CODE_SIZE) {
			ucrypt_log_error(UCRYPT_ERR_ATTR_INVALID_CODE);
			return UCRYPT_ERR_ATTR_INVALID_CODE;
		}
		payload_start_pos += ATTR_CODE_SIZE;
		load16(buff, &attrib_code);
		switch (attrib_code) {
		case 0:
			break;
		case 1:
			memset(buff, 0, MAX_ATTR_LEN_SIZE);

			if (fread(buff, 1, MAX_PAYLOAD_SIZE, infp) != MAX_PAYLOAD_SIZE) {
				ucrypt_log_error(UCRYPT_ERR_ATTR_INVALID_LEN);
				return UCRYPT_ERR_ATTR_INVALID_LEN;
			}
			load64(buff, file_size);
			payload_start_pos += MAX_PAYLOAD_SIZE;
			return payload_start_pos;
			break;
		default:
			memset(buff, 0, MAX_ATTR_LEN_SIZE);
			if (fread(buff, 1, ATTR_LEN_SIZE, infp) != ATTR_LEN_SIZE) {
				ucrypt_log_error(UCRYPT_ERR_ATTR_INVALID_LEN);
				return UCRYPT_ERR_ATTR_INVALID_LEN;
			}
			payload_start_pos += ATTR_LEN_SIZE;

			load16(buff, &attrib_len);
			if ((attrib_len == 0) || (attrib_len > ATTR_BUFF_LEN)) {
				ucrypt_log_error(UCRYPT_ERR_ATTR_INVALID_DATA);
				return UCRYPT_ERR_ATTR_INVALID_DATA;
			}
			fseek(infp, attrib_len, SEEK_CUR);
			payload_start_pos += attrib_len;
			break;
		}
	}
	return payload_start_pos;
}

/*
 * @@crypt_handler_attach_hmac()
 * Description : writes the HMAC data in hmac to the output stream specified
 * 				by outfp.
 */
UCRYPT_ERR crypt_handler_attach_hmac(FILE *outfp, const _uchar* hmac,
		_uint16 hmac_len) {
	_uchar buff[MAX_ATTR_LEN_SIZE];
	memset(buff, 0, MAX_ATTR_LEN_SIZE);
	store16(buff, ATTR_HMAC);
	if (fwrite(buff, 1, ATTR_CODE_SIZE, outfp) != ATTR_CODE_SIZE) {
		ucrypt_log_error(UCRYPT_ERR_FRAME_WRITE);
		return UCRYPT_ERR_HMAC_ATTACH;
	}
	memset(buff, 0, MAX_ATTR_LEN_SIZE);
	store16(buff, hmac_len);
	if (fwrite(buff, 1, ATTR_LEN_SIZE, outfp) != ATTR_LEN_SIZE) {
		ucrypt_log_error(UCRYPT_ERR_FRAME_WRITE);
		return UCRYPT_ERR_HMAC_ATTACH;
	}
	if (fwrite(hmac, 1, hmac_len, outfp) != hmac_len) {
		ucrypt_log_error(UCRYPT_ERR_FRAME_WRITE);
		return UCRYPT_ERR_HMAC_ATTACH;
	}
	return CRYPT_OK;
}

/*
 * @@crypt_handler_verfiy_hmac()
 * Description: recieves the hmac and an infpt file stream infp. Reads the
 * 				hmac stored in infp and matches it against the recieved one.
 * 				It returns true if two else it's an error.
 */
UCRYPT_ERR crypt_handler_verify_hmac(FILE *infp, const _uchar* calculated_hmac,
		_uint16 hmac_len) {
	_uint16 attrib_code, attrib_len;
	_uchar buff[MAX_ATTR_LEN_SIZE];
	_uchar loaded_hmac[HMAC_BUFF_SIZE];
	_uint64 file_size = 0;
	rewind(infp);
	while (infp) {
		memset(buff, 0, MAX_ATTR_LEN_SIZE);
		memset(loaded_hmac, 0, HMAC_BUFF_SIZE);

		if (fread(buff, 1, ATTR_CODE_SIZE, infp) != ATTR_CODE_SIZE) {
			ucrypt_log_error(UCRYPT_ERR_ATTR_INVALID_CODE);
			return UCRYPT_ERR_ATTR_INVALID_CODE;
		}
		load16(buff, &attrib_code);
		switch (attrib_code) {
		case 0:
			/* end marker just stop-- we found end marker before we could
			 * find HMAC
			 */
			return UCRYPT_ERR_ATTR_INVALID_CODE;
			break;
		case 1:
			memset(buff, 0, MAX_ATTR_LEN_SIZE);
			if (fread(buff, 1, MAX_PAYLOAD_SIZE, infp) != MAX_PAYLOAD_SIZE) {
				ucrypt_log_error(UCRYPT_ERR_ATTR_INVALID_LEN);
				return UCRYPT_ERR_ATTR_INVALID_LEN;
			}
			load64(buff, &file_size);
			fseek(infp, file_size, SEEK_CUR);
			break;

		default:
			memset(buff, 0, MAX_ATTR_LEN_SIZE);
			if (fread(buff, 1, ATTR_LEN_SIZE, infp) != ATTR_LEN_SIZE) {
				ucrypt_log_error(UCRYPT_ERR_ATTR_INVALID_LEN);
				return UCRYPT_ERR_ATTR_INVALID_LEN;
			}

			load16(buff, &attrib_len);
			if ((attrib_len == 0) || (attrib_len > ATTR_BUFF_LEN)) {
				ucrypt_log_error(UCRYPT_ERR_ATTR_INVALID_LEN);
				return UCRYPT_ERR_ATTR_INVALID_LEN;
			}

			if (attrib_code == 5) {
				if (fread(loaded_hmac, 1, attrib_len, infp) != attrib_len) {
					ucrypt_log_error(UCRYPT_ERR_ATTR_INVALID_DATA);
					return UCRYPT_ERR_ATTR_INVALID_DATA;
				}
				if (attrib_len == hmac_len) {
					if (memcmp(calculated_hmac, loaded_hmac, attrib_len) == 0) {
						return CRYPT_OK;
					}
				}
				ucrypt_log_error(UCRYPT_ERR_HMAC_VERIFY);
				return UCRYPT_ERR_HMAC_VERIFY;
			}
			fseek(infp, attrib_len, SEEK_CUR);
			break;
		} //end of switch
	} //end of while
	return CRYPT_OK;
}
