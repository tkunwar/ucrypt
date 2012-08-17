#include "ucrypt_crypt_handler.h"

void crypt_handler_init(crypt_handler_state *state, crypt_algo_t crypt_algo,
		const unsigned char *key, _uint16 key_len, const unsigned char *iv,
		_uint16 iv_len) {
	memcpy(state->iv, iv, iv_len);
	memcpy(state->key, key, key_len);
	state->crypt_algo = crypt_algo;
	state->iv_len = iv_len;
	state->key_len = key_len;
}

UCRYPT_ERR crypt_handler_encrypt(crypt_handler_state *state, FILE *infp,
		FILE *outfp) {
	unsigned char pt_buffer[CRYPT_BUFF_SIZE];
	unsigned char ct_buffer[CRYPT_BUFF_SIZE];
	unsigned char buff[10]; /*will be used for converting integers */
	unsigned char hmac_buff[HMAC_BUFF_SIZE];
	hmac_state hmac;
	_int16 lib_error;
	symmetric_CTR ctr;
	_uint64 file_size = get_file_size(infp);
	_int16 bytes_read = -1;
	_uint64 bytes_encrypted = 0;
	_uint32 hmac_len;

	/*time to start encryption process */
	switch (state->crypt_algo) {
	case BLOWFISH:
		/*register blowfish first*/
		if (register_cipher(&blowfish_desc) == -1) {
			serror("Failed to register AES");
			return UCRYPT_ERR_CRYPT;
		}
		/*start up ctr mode*/
		if ((lib_error = ctr_start(find_cipher("blowfish"), state->iv,
				state->key, state->key_len, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr))
				!= CRYPT_OK) {
			var_error("ctr_start error: %s\n", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}

		memset(buff, 0, 10);
		if (store16(buff, 1) == TRUE) {
			/*write it*/
			if (fwrite(buff, 1, ATTR_CODE_SIZE, outfp) != ATTR_CODE_SIZE) {
				serror("Failed to write frame markers.");
				return UCRYPT_ERR_CRYPT;
			}
		}
		memset(buff, 0, 10);
		if (store64(buff, file_size) == TRUE) {
			if (fwrite(buff, 1, MAX_PAYLOAD_SIZE, outfp) != MAX_PAYLOAD_SIZE) {
				serror("Failed to write frame markers.");
				return UCRYPT_ERR_CRYPT;
			}
		}
		/*initialize hmac*/
		if (register_hash(&sha256_desc) == -1) {
			serror("Error registering SHA256");
			return UCRYPT_ERR_CRYPT;
		}
		if ((lib_error = hmac_init(&hmac, find_hash("sha256"), state->key,
				state->key_len)) != CRYPT_OK) {
			var_error("Error setting up hmac: %s", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}
		sdebug("Ready to encrypt..\nEncryption in progress..");

		while ((bytes_read = fread(pt_buffer, 1, CRYPT_BUFF_SIZE, infp)) > 0) {
			if ((lib_error = ctr_encrypt(pt_buffer, ct_buffer, bytes_read, &ctr))
					!= CRYPT_OK) {
				var_error("ctr_encrypt error: %s\n",
						error_to_string(lib_error));
				return UCRYPT_ERR_CRYPT;
			}
			/*put current encrypted block to hmac_process */
			if ((lib_error = hmac_process(&hmac, ct_buffer, bytes_read))
					!= CRYPT_OK) {
				var_error("Error processing hmac : %s",
						error_to_string(lib_error));
				return UCRYPT_ERR_CRYPT;
			}
			/*write the encrypted block to outfp*/
			if (fwrite(ct_buffer, 1, bytes_read, outfp) != bytes_read) {
				serror("Failed to write output stream ");
				return UCRYPT_ERR_CRYPT;
			}
			bytes_encrypted += bytes_read;
			/*we stop when we have read file_size no. of bytes*/
			if (bytes_encrypted == file_size)
				break;
		}
		/*check to see if any read error occurred */
		if (bytes_read < 0) {
			serror("Could not complete encryption");
			return UCRYPT_ERR_CRYPT;
		}
		var_debug("Encrypted %llu bytes", bytes_encrypted);
		/*get result of hmac*/
		hmac_len = sizeof(hmac_buff);
		if ((lib_error = hmac_done(&hmac, hmac_buff, &hmac_len)) != CRYPT_OK) {
			var_error("Error finishing hmac : %s", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}
		var_debug("Calculated hmac %lu bytes long", hmac_len);
		/*save hmac to file */
		if (crypt_handler_attach_hmac(outfp, hmac_buff, hmac_len) != UCRYPT_OK) {
			serror("Failed to save HMAC");
			return UCRYPT_ERR_CRYPT;
		}
		/*terminate the stream*/
		if ((lib_error = ctr_done(&ctr)) != CRYPT_OK) {
			var_error("ctr_done error: %s", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}
		/*cleanup ctr state*/
		zeromem(&ctr, sizeof(ctr));
		break;
	case CAST:
		/*register cast5 first*/
		if (register_cipher(&cast5_desc) == -1) {
			serror("Failed to register CAST");
			return UCRYPT_ERR_CRYPT;
		}
		/*start up ctr mode*/
		if ((lib_error = ctr_start(find_cipher("cast5"), state->iv, state->key,
				state->key_len, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr))
				!= CRYPT_OK) {
			var_error("ctr_start error: %s\n", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}

		/* we are ready to begin encryption but before we do that lets add the
		 * payload frame marker*/
		/* this is what we are gonna add
		 * 2 bytes for attrib_code using store16() attr_code  is 1 for payload
		 * 8 bytes for file_size using store64()
		 */
		memset(buff, 0, 10);
		if (store16(buff, 1) == TRUE) {
			/*write it*/
			if (fwrite(buff, 1, ATTR_CODE_SIZE, outfp) != ATTR_CODE_SIZE) {
				serror("Failed to write frame markers.");
				return UCRYPT_ERR_CRYPT;
			}
		}
		memset(buff, 0, 10);
		if (store64(buff, file_size) == TRUE) {
			/*write it*/
			if (fwrite(buff, 1, MAX_PAYLOAD_SIZE, outfp) != MAX_PAYLOAD_SIZE) {
				serror("Failed to write frame markers.");
				return UCRYPT_ERR_CRYPT;
			}
		}
		/*initialize hmac*/
		if (register_hash(&sha256_desc) == -1) {
			serror("Error registering SHA256");
			return UCRYPT_ERR_CRYPT;
		}
		if ((lib_error = hmac_init(&hmac, find_hash("sha256"), state->key,
				state->key_len)) != CRYPT_OK) {
			var_error("Error setting up hmac: %s", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}
		serror("Ready to encrypt..\nEncryption in progress..");

		while ((bytes_read = fread(pt_buffer, 1, CRYPT_BUFF_SIZE, infp)) > 0) {
			/*we can compute hmac as we proceed */
			if ((lib_error = ctr_encrypt(pt_buffer, ct_buffer, bytes_read, &ctr))
					!= CRYPT_OK) {
				var_error("ctr_encrypt error: %s\n",
						error_to_string(lib_error));
				return UCRYPT_ERR_CRYPT;
			}
			/*put current encrypted block to hmac_process */
			if ((lib_error = hmac_process(&hmac, ct_buffer, bytes_read))
					!= CRYPT_OK) {
				var_error("Error processing hmac : %s",
						error_to_string(lib_error));
				return UCRYPT_ERR_CRYPT;
			}
			/*write the encrypted block to outfp*/
			if (fwrite(ct_buffer, 1, bytes_read, outfp) != bytes_read) {
				serror("Could write to output stream");
				return UCRYPT_ERR_CRYPT;
			}
			bytes_encrypted += bytes_read;
			/*we stop when we have read file_size no. of bytes*/
			if (bytes_encrypted == file_size)
				break;
		}
		/*check to see if any read error occurred */
		if (bytes_read < 0) {
			serror("Could not complete encryption");
			return UCRYPT_ERR_CRYPT;
		}
		var_error("Encrypted %llu bytes", bytes_encrypted);
		/*get result of hmac*/
		hmac_len = sizeof(hmac_buff);
		if ((lib_error = hmac_done(&hmac, hmac_buff, &hmac_len)) != CRYPT_OK) {
			var_error("\nError finishing hmac : %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}
		fprintf(UCRYPT_STDERR, "\nCalculated hmac %lu bytes long", hmac_len);
		/*save hmac to file */
		if (crypt_handler_attach_hmac(outfp, hmac_buff, hmac_len) != UCRYPT_OK) {
			serror("Failed to save HMAC");
			return UCRYPT_ERR_CRYPT;
		}
		/*terminate the stream*/
		if ((lib_error = ctr_done(&ctr)) != CRYPT_OK) {
			var_error("ctr_done error: %s", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}
		/*cleanup ctr state*/
		zeromem(&ctr, sizeof(ctr));
		break;
	case AES:
		/*register AES first*/
		if (register_cipher(&aes_desc) == -1) {
			serror("Failed to register AES");
			return UCRYPT_ERR_CRYPT;
		}
		/*start up ctr mode*/
		if ((lib_error = ctr_start(find_cipher("aes"), state->iv, state->key,
				state->key_len, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr))
				!= CRYPT_OK) {
			var_error("ctr_start error: %s\n", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}

		/*we are ready to begin encryption but before we do that lets add the payload frame marker*/
		/*this is what we are gonna add
		 * 2 bytes for attrib_code using store16() attr_code  is 1 for payload
		 * 8 bytes for file_size using store64()
		 */
		memset(buff, 0, 10);
		if (store16(buff, 1) == TRUE) {
			/*write it*/
			if (fwrite(buff, 1, ATTR_CODE_SIZE, outfp) != ATTR_CODE_SIZE) {
				serror("Failed to write frame markers.");
				return UCRYPT_ERR_CRYPT;
			}
		}
		memset(buff, 0, 10);
		if (store64(buff, file_size) == TRUE) {
			/*write it*/
			if (fwrite(buff, 1, MAX_PAYLOAD_SIZE, outfp) != MAX_PAYLOAD_SIZE) {
				serror("Failed to write frame markers.");
				return UCRYPT_ERR_CRYPT;
			}
		}
		/*initialize hmac*/
		if (register_hash(&sha256_desc) == -1) {
			serror("Error registering SHA256");
			return UCRYPT_ERR_CRYPT;
		}
		if ((lib_error = hmac_init(&hmac, find_hash("sha256"), state->key,
				state->key_len)) != CRYPT_OK) {
			var_error("Error setting up hmac: %s", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}

		sdebug( "Encryption in progress..");

		while ((bytes_read = fread(pt_buffer, 1, CRYPT_BUFF_SIZE, infp)) > 0) {
			/*we can compute hmac as we proceed */
			if ((lib_error = ctr_encrypt(pt_buffer, ct_buffer, bytes_read, &ctr))
					!= CRYPT_OK) {
				var_error("ctr_encrypt error: %s\n",
						error_to_string(lib_error));
				return UCRYPT_ERR_CRYPT;
			}
			/*put current encrypted block to hmac_process */
			if ((lib_error = hmac_process(&hmac, ct_buffer, bytes_read))
					!= CRYPT_OK) {
				var_error( "Error processing hmac : %s",
						error_to_string(lib_error));
				return UCRYPT_ERR_CRYPT;
			}
			/*write the encrypted block to outfp*/
			if (fwrite(ct_buffer, 1, bytes_read, outfp) != bytes_read) {
				serror("Failed to write to output stream");
				return UCRYPT_ERR_CRYPT;
			}
			bytes_encrypted += bytes_read;
			/*we stop when we have read file_size no. of bytes*/
			if (bytes_encrypted == file_size)
				break;
		}
		/*check to see if any read error occurred */
		if (bytes_read < 0) {
			serror("Could not complete encryption");
			return UCRYPT_ERR_CRYPT;
		}
		var_error("Encrypted %llu bytes", bytes_encrypted);
		/*get result of hmac*/
		hmac_len = sizeof(hmac_buff);
		if ((lib_error = hmac_done(&hmac, hmac_buff, &hmac_len)) != CRYPT_OK) {
			var_error("Error finishing hmac : %s", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}
		var_debug( "Calculated hmac %lu bytes long", hmac_len);
		/*save hmac to file */
		if (crypt_handler_attach_hmac(outfp, hmac_buff, hmac_len) != UCRYPT_OK) {
			serror("Failed to save HMAC");
			return UCRYPT_ERR_CRYPT;
		}
		/*terminate the stream*/
		if ((lib_error = ctr_done(&ctr)) != CRYPT_OK) {
			var_error("ctr_done error: %s", error_to_string(lib_error));
			return UCRYPT_ERR_CRYPT;
		}
		/*cleanup ctr state*/
		zeromem(&ctr, sizeof(ctr));
		break;
	default:
		break;
	} //end of switch
	return CRYPT_OK;
}
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
	_uint64 file_size = 0, payload_start_pos = 0, decrypted_bytes = 0,
			 bytes_to_read = 0;
	/*reset infp to begining of file*/
	rewind(infp);
	switch (state->crypt_algo) {
	case BLOWFISH:
		/*register blowfish first*/
		if (register_cipher(&blowfish_desc) == -1) {
			fprintf(UCRYPT_STDERR, "\nFailed to register AES");
			return UCRYPT_ERR_DCRYPT;
		}
		/*start up ctr mode*/
		if ((lib_error = ctr_start(find_cipher("blowfish"), state->iv,
				state->key, state->key_len, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr))
				!= CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nctr_start error: %s\n",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}
		payload_start_pos = crypt_handler_get_payload_info(infp,
				&file_size);
		/*use ctr_setiv as we want to decrypt*/
		if ((lib_error = ctr_setiv(state->iv, state->iv_len, &ctr))
				!= CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nctr_setiv error: %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}
		/*initialize hmac*/
		if (register_hash(&sha256_desc) == -1) {
			fprintf(UCRYPT_STDERR, "\nError registering SHA256");
			/*return failure*/
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
			/*put current encrypted block to hmac_process ,remember that we have calculated hmac of encrypted data only*/
			if ((lib_error = hmac_process(&hmac, ct_buffer, bytes_read))
					!= CRYPT_OK) {
				fprintf(UCRYPT_STDERR, "\nError processing hmac : %s",
						error_to_string(lib_error));
				return UCRYPT_ERR_DCRYPT;
			}
			/*write the decrypted block to outfp*/
			if (fwrite(pt_buffer, 1, bytes_read, outfp) != bytes_read) {
				serror("Failed to write decrypted block");
				return UCRYPT_ERR_DCRYPT;
			}

			decrypted_bytes += bytes_read;
			bytes_to_read = file_size - decrypted_bytes;
			bytes_to_read =
					(bytes_to_read >= CRYPT_BUFF_SIZE) ?
							CRYPT_BUFF_SIZE : bytes_to_read;
			/*stop reading further when we have already decrypted file_size no. of bytes */
			if (decrypted_bytes == file_size)
				break;
		}
		/*check to see if any read error occurred */
		if (bytes_read < 0) {
			serror("A read error occurred");
			return UCRYPT_ERR_DCRYPT;
		}
		/*get result of hmac*/
		hmac_len = sizeof(hmac_buff);
		if ((lib_error = hmac_done(&hmac, hmac_buff, &hmac_len)) != CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nError finishing hmac : %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}

		/*now lets verify hmac*/
		if (crypt_handler_verify_hmac(infp, hmac_buff, hmac_len) != CRYPT_OK) {
			serror("HMAC verification failed");
			return UCRYPT_ERR_HMAC_VERIFY;
		}
		/*terminate the stream*/
		if ((lib_error = ctr_done(&ctr)) != CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nctr_done error: %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}
		/*cleanup ctr state*/
		zeromem(&ctr, sizeof(ctr));
		break;
	case CAST:
		/*register cast5 first*/
		if (register_cipher(&cast5_desc) == -1) {
			fprintf(UCRYPT_STDERR, "\nFailed to register AES");
			return UCRYPT_ERR_DCRYPT;
		}
		/*start up ctr mode*/
		if ((lib_error = ctr_start(find_cipher("cast5"), state->iv, state->key,
				state->key_len, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr))
				!= CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nctr_start error: %s\n",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}
		if (UCRYPT_DEBUG)
			fprintf(UCRYPT_STDERR, "\nDetermining payload position");
		if ((payload_start_pos = crypt_handler_get_payload_info(infp,
				&file_size)) != 0) {
			if (UCRYPT_DEBUG)
				fprintf(UCRYPT_STDERR,
						"\nPayload starts @ :%llu  File size (actual payload): %llu bytes",
						payload_start_pos, file_size);
		}
		/*use ctr_setiv as we want to decrypt*/
		if ((lib_error = ctr_setiv(state->iv, state->iv_len, &ctr))
				!= CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nctr_setiv error: %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}
		/*initialize hmac*/
		if (register_hash(&sha256_desc) == -1) {
			fprintf(UCRYPT_STDERR, "\nError registering SHA256");
			/*return failure*/
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
			/*put current encrypted block to hmac_process ,remember that we have calculated hmac of encrypted data only*/
			if ((lib_error = hmac_process(&hmac, ct_buffer, bytes_read))
					!= CRYPT_OK) {
				fprintf(UCRYPT_STDERR, "\nError processing hmac : %s",
						error_to_string(lib_error));
				return UCRYPT_ERR_DCRYPT;
			}
			/*write the decrypted block to outfp*/
			if (fwrite(pt_buffer, 1, bytes_read, outfp) != bytes_read) {
				serror("Failed to write decrypted block");
				return UCRYPT_ERR_FILE_WRITE;
			}
			decrypted_bytes += bytes_read;
			bytes_to_read = file_size - decrypted_bytes;
			bytes_to_read =
					(bytes_to_read >= CRYPT_BUFF_SIZE) ?
							CRYPT_BUFF_SIZE : bytes_to_read;
			/*stop reading further when we have already decrypted file_size no. of bytes */
			if (decrypted_bytes == file_size)
				break;
		}
		/*check to see if any read error occurred */
		if (bytes_read < 0) {
			serror("A read error occurred");
			return UCRYPT_ERR_FILE_READ;
		}

		/*get result of hmac*/
		hmac_len = sizeof(hmac_buff);
		if ((lib_error = hmac_done(&hmac, hmac_buff, &hmac_len)) != CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nError finishing hmac : %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}

		/*now lets verify hmac*/
		if (crypt_handler_verify_hmac(infp, hmac_buff, hmac_len) != CRYPT_OK) {
			serror("HMAC verification failed");
			return UCRYPT_ERR_HMAC_VERIFY;
		}
		/*terminate the stream*/
		if ((lib_error = ctr_done(&ctr)) != CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nctr_done error: %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}
		/*cleanup ctr state*/
		zeromem(&ctr, sizeof(ctr));
		break;
	case AES:
		/*register AES first*/
		if (register_cipher(&aes_desc) == -1) {
			fprintf(UCRYPT_STDERR, "\nFailed to register AES");
			return UCRYPT_ERR_DCRYPT;
		}
		/*start up ctr mode*/
		if ((lib_error = ctr_start(find_cipher("aes"), state->iv, state->key,
				state->key_len, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr))
				!= CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nctr_start error: %s\n",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}
		if (UCRYPT_DEBUG)
			fprintf(UCRYPT_STDERR, "\nDetermining payload position");
		if ((payload_start_pos = crypt_handler_get_payload_info(infp,
				&file_size)) != 0) {
			if (UCRYPT_DEBUG)
				fprintf(UCRYPT_STDERR,
						"\nPayload starts @ :%llu  File size (actual payload): %llu bytes",
						payload_start_pos, file_size);
		}
		/*use ctr_setiv as we want to decrypt*/
		if ((lib_error = ctr_setiv(state->iv, state->iv_len, &ctr))
				!= CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nctr_setiv error: %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}
		/*initialize hmac*/
		if (register_hash(&sha256_desc) == -1) {
			fprintf(UCRYPT_STDERR, "\nError registering SHA256");
			/*return failure*/
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
			/*put current encrypted block to hmac_process ,remember that we have calculated hmac of encrypted data only*/
			if ((lib_error = hmac_process(&hmac, ct_buffer, bytes_read))
					!= CRYPT_OK) {
				fprintf(UCRYPT_STDERR, "\nError processing hmac : %s",
						error_to_string(lib_error));
				return UCRYPT_ERR_DCRYPT;
			}
			/*write the decrypted block to outfp*/
			if (fwrite(pt_buffer, 1, bytes_read, outfp) != bytes_read) {
				serror("Failed to write decrypted block");
				return UCRYPT_ERR_FILE_WRITE;
			}
			/*calculate new size of buffer which we have to read to
			 * update bytes_to_read
			 */

			decrypted_bytes += bytes_read;
			bytes_to_read = file_size - decrypted_bytes;
			bytes_to_read =
					(bytes_to_read >= CRYPT_BUFF_SIZE) ?
							CRYPT_BUFF_SIZE : bytes_to_read;
			/*stop reading further when we have already decrypted file_size no. of bytes */
			if (decrypted_bytes == file_size){
				var_debug("Wrote %llu bytes",decrypted_bytes);
				break;
			}

		}
		/*check to see if any read error occurred */
		if (bytes_read < 0) {
			serror("A read error occurred");
			return UCRYPT_ERR_FILE_READ;
		}
		/*note : there is a difference in the source file and the decrypted file
		 * what i can see is that decrypted file is always a factor of 16 (the block size) so may be due to ctr mode
		 * there is automatic padding of some bytes ,also some bytes are being dropped from the source file
		 */

		/*get result of hmac*/
		hmac_len = sizeof(hmac_buff);
		if ((lib_error = hmac_done(&hmac, hmac_buff, &hmac_len)) != CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nError finishing hmac : %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}

		/*now lets verify hmac*/
		if (crypt_handler_verify_hmac(infp, hmac_buff, hmac_len) != CRYPT_OK) {
			serror("HMAC verification failed");
			return UCRYPT_ERR_HMAC_VERIFY;
		}

		/*terminate the stream*/
		if ((lib_error = ctr_done(&ctr)) != CRYPT_OK) {
			fprintf(UCRYPT_STDERR, "\nctr_done error: %s",
					error_to_string(lib_error));
			return UCRYPT_ERR_DCRYPT;
		}
		/*cleanup ctr state*/
		zeromem(&ctr, sizeof(ctr));
		break;
	default:
		serror("Unsupported algorithm");
		return UCRYPT_ERR_DCRYPT;
		break;
	}
	return UCRYPT_OK;
}

_uint64 crypt_handler_get_payload_info(FILE *infp, _uint64 *file_size) {
	/*this routine will return payload_begin_pos in two ways:
	 * first return the position of payload from begining of file in bytes
	 * also the infp will be moved to that position accurately
	 * it's upon the caller to decide which one to choose
	 */
	_uint64 payload_start_pos = 0;
	_uint16 attrib_code, attrib_len;
	/*so how do we do it ??
	 * 1.we read  first double octet which will give us attr_code and then
	 * 2.by reading the next  double octets we determine the attrib_len
	 * 3.then instead of loading the attr_data we simple seek forward attrib_len no. of bytes and
	 * repeat step 1 and keep updating payload_starrt_pos untill we find attr_code 1 . then we return
	 * payload_start_pos.
	 */_uchar buff[10];
	rewind(infp);
	while (infp) {
		/* reset buffers*/
		memset(buff, 0, 10);
		/*we read while either eof is not reached or we encounter attr_code 0
		 */
		/* first read attr_code then decode it */
		if (fread(buff, 1, ATTR_CODE_SIZE, infp) != ATTR_CODE_SIZE) {
			fprintf(UCRYPT_STDERR,
					"\nFrame Read Error: ATTR_CODE missing or invalid");
			ucrypt_log_error(35);
			return FALSE;
		}
		/*update payload_start_pos*/
		payload_start_pos += ATTR_CODE_SIZE;
		if (load16(buff, &attrib_code) == TRUE) {
			switch (attrib_code) {
			case 0: /*end marker just stop
			 */
				break;
			case 1:
				/*give palyload msg and stop
				 */
				memset(buff, 0, 10);

				if (fread(buff, 1, MAX_PAYLOAD_SIZE, infp) != MAX_PAYLOAD_SIZE) {
					fprintf(UCRYPT_STDERR,
							"\nFrame Read Error: ATTR_LEN missing or invalid");
					ucrypt_log_error(35);
					return FALSE;
				}
				if (!load64(buff, file_size)) {
					fprintf(UCRYPT_STDERR,
							"\nFrame Read Error: ATTR_LEN (:payload) missing or invalid");
					ucrypt_log_error(35);
					return FALSE;
				}
				/*update payload_start_pos*/
				payload_start_pos += MAX_PAYLOAD_SIZE;
				return payload_start_pos;
				break;
			default:
				/*now read attr_len
				 */
				memset(buff, 0, 10);
				if (fread(buff, 1, ATTR_LEN_SIZE, infp) != ATTR_LEN_SIZE) {
					fprintf(UCRYPT_STDERR,
							"\nFrame Read Error: ATTR_LEN missing or invalid");
					ucrypt_log_error(35);
					return FALSE;

				}
				/*update payload_start_pos*/
				payload_start_pos += ATTR_LEN_SIZE;

				if (load16(buff, &attrib_len) == TRUE) {
					if ((attrib_len == 0) || (attrib_len > ATTR_MAX_LEN)) {
						fprintf(UCRYPT_STDERR,
								"\nFrame Read Error: Invalid ATTR_LEN");
						return FALSE;
					}
					/*seek forward attrib_len no. of bytes */
					fseek(infp, attrib_len, SEEK_CUR);
					/*update payload_start_pos*/
					payload_start_pos += attrib_len;
				}
				break;
			}
		}
	}
	return payload_start_pos;
}

UCRYPT_ERR crypt_handler_attach_hmac(FILE *outfp, const _uchar* hmac,
		_uint16 hmac_len) {
	/*for hmac code is 5*/
	_uchar buff[4];
	memset(buff, 0, 4);
	if (store16(buff, 5) == TRUE) {
		/*write it*/
		if (fwrite(buff, 1, ATTR_CODE_SIZE, outfp) != ATTR_CODE_SIZE) {
			fprintf(UCRYPT_STDERR, "\nFailed to write frame markers.");
			return UCRYPT_ERR_HMAC_ATTACH;
		}
	}
	memset(buff, 0, 4);
	if (store16(buff, hmac_len) == TRUE) {
		/*write it*/
		if (fwrite(buff, 1, ATTR_LEN_SIZE, outfp) != ATTR_LEN_SIZE) {
			fprintf(UCRYPT_STDERR, "\nFailed to write frame markers.");
			return UCRYPT_ERR_HMAC_ATTACH;
		}
	}
	/*now save the hmac*/
	if (fwrite(hmac, 1, hmac_len, outfp) != hmac_len) {
		return UCRYPT_ERR_HMAC_ATTACH;
	}
	return CRYPT_OK;
}

UCRYPT_ERR crypt_handler_verify_hmac(FILE *infp, const _uchar* calculated_hmac,
		_uint16 hmac_len) {
	/*here we match the calculated and loaded hmac
	 */
	/*search for attr_code in file and if found fll attr with the attr_value*/
	_uint16 attrib_code, attrib_len;
	unsigned char buff[10];
	_uchar loaded_hmac[HMAC_BUFF_SIZE];
	_uint64 file_size = 0;
	rewind(infp);
	while (infp) {
		/* reset buffers*/
		memset(buff, 0, 10);
		memset(loaded_hmac, 0, HMAC_BUFF_SIZE);

		/* first read attr_code then decode it */
		if (fread(buff, 1, ATTR_CODE_SIZE, infp) != ATTR_CODE_SIZE) {
			/*check if it is eof thing **/
			fprintf(UCRYPT_STDERR,
					"\nFrame Read Error: ATTR_CODE missing or invalid");
			return UCRYPT_ERR_HMAC_VERIFY;
		}
		if (load16(buff, &attrib_code) == TRUE) {
			switch (attrib_code) {
			case 0:
				/*end marker just stop-- we found end marker before we could
				 * find HMAC
				 */
				return UCRYPT_ERR_HMAC_VERIFY;
				break;
			case 1:
				/*read attr_len of MAX_PALOAD_SIZE and seek that many bytes
				 */
				memset(buff, 0, 10);
				if (fread(buff, 1, MAX_PAYLOAD_SIZE, infp) != MAX_PAYLOAD_SIZE) {
					fprintf(UCRYPT_STDERR,
							"\nFrame Read Error: ATTR_LEN missing or invalid");
					return UCRYPT_ERR_HMAC_VERIFY;
				}
				if (!load64(buff, &file_size)) {
					fprintf(UCRYPT_STDERR,
							"\nFrame Read Error: ATTR_LEN (:payload) missing or invalid");
					return UCRYPT_ERR_HMAC_VERIFY;
				}
				/*seek forward file_size  no. of bytes */
				fseek(infp, file_size, SEEK_CUR);
				break;

			default:
				memset(buff, 0, 10);
				/*now read attr_len
				 */
				if (fread(buff, 1, ATTR_LEN_SIZE, infp) != ATTR_LEN_SIZE) {
					fprintf(UCRYPT_STDERR,
							"\nFrame Read Error: ATTR_LEN missing or invalid");
					return UCRYPT_ERR_HMAC_VERIFY;
				}

				if (load16(buff, &attrib_len)) {
					/*a random check :for a non-zero attrib code attr_len cant be 0*/
					if ((attrib_len == 0) || (attrib_len > ATTR_MAX_LEN)) {
						fprintf(UCRYPT_STDERR,
								"\nFrame Read Error: Invalid ATTR_LEN attr_len 0");
						return UCRYPT_ERR_HMAC_VERIFY;
					}

					if (attrib_code == 5) {
						if (fread(loaded_hmac, 1, attrib_len, infp)
								!= attrib_len) {

							fprintf(UCRYPT_STDERR,
									"\nFrame Read Error: ATTR_DATA (HMAC)missing or invalid");
							return UCRYPT_ERR_HMAC_VERIFY;
						}
						if (attrib_len == hmac_len) {

							if (memcmp(calculated_hmac, loaded_hmac, attrib_len)
									== 0) {
								return CRYPT_OK;
							}
						}
						return UCRYPT_ERR_HMAC_VERIFY;
					}
					/*here also we fseek attrib_len no. of bytes*/
					fseek(infp, attrib_len, SEEK_CUR);
				} else
					return UCRYPT_ERR_HMAC_VERIFY;
				break;
			} //end of switch
		} // end of outer if

	} //end of while

	return CRYPT_OK;
}

