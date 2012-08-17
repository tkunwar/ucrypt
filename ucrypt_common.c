#include "ucrypt_common.h"
//access the error code thrown by routines in standard library

/* @@file_exists()
 * Description : check if file exists. if it exists return true else
 * 				return false
 * @param filename: filename which existence is to be checked
 */UCRYPT_BOOL file_exists(char *filename) {
	FILE *fptr = NULL;
	fptr = fopen(filename, "rb");
	if (!fptr) {
		return FALSE;
	}
	fclose(fptr);
	return TRUE;
}

/* @@get_file_size()
 * Description : returns size of a file in bytes
 * @param infp: The file pointer of input file
 */_uint64 get_file_size(FILE *infp) {
	_uint64 file_size;
	/*go to beginning first*/
	rewind(infp);
	/*seek to end of file*/
	fseek(infp, 0, SEEK_END);
	file_size = ftell(infp);
	/*goto beginning of file again*/
	fseek(infp, 0, SEEK_SET);
	return file_size;
}

UCRYPT_BOOL store16(_uchar *buff, _uint16 num) {
	if (sizeof(buff) >= 2) {
		buff[0] = num >> 8 & 0x00FF;
		buff[1] = num & 0x00FF;
		return TRUE;
	}
	return FALSE;
}

UCRYPT_BOOL load16(_uchar *buff, _uint16 *num) {
	*num = 0x0000;
	*num = *num | (_uint16) buff[0];
	*num = (*num << 8) | (_uint16) buff[1];
	return TRUE;
}

UCRYPT_BOOL store32(_uchar *buff, _uint32 num) {
	if (sizeof(buff) >= 4) {
		buff[0] = (num >> 24) & 0x000000FF;
		buff[1] = (num >> 16) & 0x000000FF;
		buff[2] = (num >> 8) & 0x000000FF;
		buff[3] = (num) & 0x000000FF;
		return TRUE;
	}
	return FALSE;
}

UCRYPT_BOOL load32(_uchar *buff, _uint32 *num) {
	*num = 0x00000000;
	*num = *num | (_uint16) buff[0];
	*num = (*num << 8) | (_uint16) buff[1];
	*num = (*num << 8) | (_uint16) buff[2];
	*num = (*num << 8) | (_uint16) buff[3];
	return TRUE;
}

UCRYPT_BOOL store64(_uchar *buff, _uint64 num) {
	/*
	 * it't not possible to determine if the passed array is of correct length
	 */
	if (sizeof(buff) >= 8) {
		buff[0] = (num >> 56) & 0x00000000000000FF;
		buff[1] = (num >> 48) & 0x00000000000000FF;
		buff[2] = (num >> 40) & 0x00000000000000FF;
		buff[3] = (num >> 32) & 0x00000000000000FF;
		buff[4] = (num >> 24) & 0x00000000000000FF;
		buff[5] = (num >> 16) & 0x00000000000000FF;
		buff[6] = (num >> 8) & 0x00000000000000FF;
		buff[7] = (num) & 0x00000000000000FF;
		return TRUE;
	}
	return FALSE;
}

UCRYPT_BOOL load64(_uchar *buff, _uint64 *num) {
	*num = 0x0000000000000000;
	*num = *num | (_uint16) buff[0];
	*num = (*num << 8) | (_uint16) buff[1];
	*num = (*num << 8) | (_uint16) buff[2];
	*num = (*num << 8) | (_uint16) buff[3];
	*num = (*num << 8) | (_uint16) buff[4];
	*num = (*num << 8) | (_uint16) buff[5];
	*num = (*num << 8) | (_uint16) buff[6];
	*num = (*num << 8) | (_uint16) buff[7];
	return TRUE;
}

void load_store_test() {
	_uint16 num1 = 49997, num2;
	_uint32 num3 = 4134967295, num4;
	_uint64 num5 = 1743674407360922161, num6;
	_uchar buff[10];
	fprintf(UCRYPT_STDOUT, "\nTesting for 16,32,64 bit load,store routines...");
	fprintf(UCRYPT_STDOUT, "\nTesting 16 bit store: num is: %d", num1);
	if (store16(buff, num1)) {
		fprintf(UCRYPT_STDOUT, "\n16 bit store: byte sequence :%d %d ...OK",
				buff[0], buff[1]);
	} else {
		fprintf(UCRYPT_STDOUT, "\n16 bit store: ...FAILED");
	}
	fprintf(UCRYPT_STDOUT, "\nTesting 16 bit load:");
	if (load16(buff, &num2)) {
		fprintf(UCRYPT_STDOUT, "\n16 bit load :");
		if (num1 == num2)
			fprintf(UCRYPT_STDOUT, "...OK");
		else
			fprintf(UCRYPT_STDOUT, "...FAILED");
	}
	fprintf(UCRYPT_STDOUT, "\nTesting 32 bit store: num is: %ld", num3);
	if (store32(buff, num3)) {
		fprintf(UCRYPT_STDOUT,
				"\n32 bit store: byte sequence :%d %d %d %d ...OK", buff[0],
				buff[1], buff[3], buff[4]);
	} else {
		fprintf(UCRYPT_STDOUT, "\n32 bit store:...FAILED");
	}
	fprintf(UCRYPT_STDOUT, "\nTesting 32 bit load:");
	if (load32(buff, &num4)) {
		fprintf(UCRYPT_STDOUT, "\n32 bit load :");
		if (num3 == num4)
			fprintf(UCRYPT_STDOUT, "...OK");
		else
			fprintf(UCRYPT_STDOUT, "...FAILED");
	}
	fprintf(UCRYPT_STDOUT, "\nTesting 64 bit store: num is: %lld", num5);
	if (store64(buff, num5)) {
		fprintf(UCRYPT_STDOUT,
				"\n64 bit store: byte sequence :%d %d %d %d %d %d %d %d...OK",
				buff[0], buff[1], buff[2], buff[3], buff[4], buff[5], buff[6],
				buff[7]);
	} else {
		fprintf(UCRYPT_STDOUT, "\n64 bit store:...FAILED");
	}
	fprintf(UCRYPT_STDOUT, "\nTesting 64 bit load:");
	if (load64(buff, &num6)) {
		fprintf(UCRYPT_STDOUT, "\n64 bit load :");
		if (num5 == num6)
			fprintf(UCRYPT_STDOUT, "...OK");
		else
			fprintf(UCRYPT_STDOUT, "...FAILED");
	}
}

/* _uint16 file_frame_write(file_frame frame_array,FILE *outfp);
 * UCRYPT_BOOL file_frame_get_attr(_uint16 attr_code,char *attr,FILE *infp);
 * void file_frame_raw_scan(FILE *infp);
 */_uint16 file_frame_write(file_frame frame_array[], _uint16 frame_array_size,
		FILE *outfp) {
	_uint16 i = 0;
	_uint16 frames_written = 0;
	_uchar buffer[4]; /*use it for byte packing*/
	for (i = 0; i < frame_array_size; i++) {
		memset(buffer, 0, 4);
		if (store16(buffer, frame_array[i].attr_code) == TRUE) {
			if (fwrite(buffer, 1, ATTR_CODE_SIZE, outfp) != ATTR_CODE_SIZE) {
				return frames_written;
			}
		}

		if (store16(buffer, frame_array[i].attr_len) == TRUE) {
			if (fwrite(buffer, 1, ATTR_LEN_SIZE, outfp) != ATTR_LEN_SIZE) {
				return frames_written;
			}
		}
		if (fwrite(frame_array[i].attr, 1, frame_array[i].attr_len, outfp)
				!= frame_array[i].attr_len) {
			return frames_written;
		}
		frames_written++;
	}
	return frames_written;
}

UCRYPT_BOOL file_frame_get_attr(_uint16 attr_code, _uint16 *attr_len,
		_uchar *attr, FILE *infp) {
	_uint16 attrib_code, attrib_len;
	_uchar buff[8]; // will be used for decoding attrcodes and their length
					//max. num stored will be a unsigned long long int-(8 bytes)
	_uint64 payload_size = 0;
	rewind(infp);
	while (infp) {
		/* reset buffers*/
		memset(buff, 0, 8);
//        memset(buffer, 0, ATTR_MAX_LEN);

		/* first read attr_code then decode it */
		if (fread(buff, 1, ATTR_CODE_SIZE, infp) != ATTR_CODE_SIZE) {
			fprintf(UCRYPT_STDERR,
					"\nFrame Read Error: ATTR_CODE missing or invalid");
			return FALSE;
		}

		if (load16(buff, &attrib_code) == TRUE) {
			switch (attrib_code) {
			case 0:
				//end marker just stop
				return TRUE;
				break;
			case 1:
				//read attr_len of MAX_PALOAD_SIZE and seek that many bytes
				memset(buff, 0, 8);
				if (fread(buff, 1, MAX_PAYLOAD_SIZE, infp) != MAX_PAYLOAD_SIZE) {
					fprintf(UCRYPT_STDERR,
							"\nFrame Read Error: ATTR_LEN missing or invalid");
					return FALSE;
				}
				if (!load64(buff, &payload_size)) {
					fprintf(UCRYPT_STDERR,
							"\nFrame Read Error: ATTR_LEN (:payload) missing or invalid");
					return FALSE;
				}
				/*seek forward file_size  no. of bytes */
				fseek(infp, payload_size, SEEK_CUR);
				break;
			default:
				memset(buff, 0, 8);
				//now read attr_len
				if (fread(buff, 1, ATTR_LEN_SIZE, infp) != ATTR_LEN_SIZE) {
					fprintf(UCRYPT_STDERR,
							"\nFrame Read Error: ATTR_LEN missing or invalid");
					return FALSE;
				}

				if (load16(buff, &attrib_len)) {
					/*a random check :for a non-zero attrib code attr_len cant be 0*/
					if ((attrib_len == 0) || (attrib_len > ATTR_MAX_LEN)) {
						fprintf(UCRYPT_STDERR,
								"\nFrame Read Error: Invalid ATTR_LEN");
						return FALSE;
					}

					if (attrib_code == attr_code) {
						memset(attr, 0, attrib_len);
						/* read attrib_len no. of bytes*/
						if (fread(attr, 1, attrib_len, infp) != attrib_len) {
							fprintf(UCRYPT_STDERR,
									"\nFrame Read Error: ATTR_DATA missing or invalid");
							return FALSE;
						}
//                            memcpy(attr, buffer, attrib_len);
						//set the attribute len field
						*attr_len = attrib_len;
						return TRUE;
					} else
						fseek(infp, attrib_len, SEEK_CUR);
				} else
					return FALSE;
				break;
			}
		}

	}
	return FALSE;
}

UCRYPT_BOOL file_frame_raw_scan(FILE *infp) {
	/* we will do a basic raw scan of file structure
	 * load and print in this format :
	 * ATTR_CODE        ATTR_LEN        ATTR
	 * for attr_code and attr-len do the byte level decoding
	 */
	_uint16 attrib_code, attrib_len;
	unsigned char buff[8];
	_uint64 file_size;
	char buffer[ATTR_MAX_LEN];
	fprintf(UCRYPT_STDERR,
			"\nDumping raw scan data :\n\tATTR_CODE  ATTR_LEN(in bytes)\tATTR_DATA\n\t---------  ------------\t\t------------\n");
	/*reset infp */
	rewind(infp);
	while (infp) {
		/* reset buffers*/
		memset(buff, 0, 8);
		memset(buffer, 0, ATTR_MAX_LEN);
		/*we read while either eof is not reached or we encounter attr_code 0
		 */
		/* first read attr_code then decode it */
		if (fread(buff, 1, ATTR_CODE_SIZE, infp) != ATTR_CODE_SIZE) {
			fprintf(UCRYPT_STDERR,
					"\nFrame Read Error: ATTR_CODE missing or invalid");
			ucrypt_log_error(35);
			return FALSE;
		}
		if (load16(buff, &attrib_code) == TRUE) {
			switch (attrib_code) {
			case 0: /*read attr_len and ofcourse it's going to be zero only but still verify it
			 */
				memset(buff, 0, 8);
				if (fread(buff, 1, ATTR_LEN_SIZE, infp) != ATTR_LEN_SIZE) {
					fprintf(UCRYPT_STDERR,
							"\nFrame Read Error: ATTR_LEN missing or invalid");
					ucrypt_log_error(35);
					return FALSE;
				}

				if (load16(buff, &attrib_len) == TRUE) {
					if ((attrib_len == 0)) {
						fprintf(UCRYPT_STDERR, "\n\tEOF\t\tEOF");
						return TRUE;
					}
				}
				break;
			case 1:
				/*give palyload msg and stop
				 */
				memset(buff, 0, 8);

				if (fread(buff, 1, MAX_PAYLOAD_SIZE, infp) != MAX_PAYLOAD_SIZE) {
					fprintf(UCRYPT_STDERR,
							"\nFrame Read Error: ATTR_LEN missing or invalid");
					ucrypt_log_error(35);
					return FALSE;
				}
				if (!load64(buff, &file_size)) {
					fprintf(UCRYPT_STDERR,
							"\nFrame Read Error: ATTR_LEN (:payload) missing or invalid");
					ucrypt_log_error(35);
					return FALSE;
				}
				fprintf(UCRYPT_STDERR, "\n\t1\t%10llu\t\tPAYLOAD_DATA",
						file_size);
				/*seek to file_size no. of bytes */
				fseek(infp, file_size, SEEK_CUR);
				break;

			default:
				/*now read attr_len
				 */
				memset(buff, 0, 8);
				if (fread(buff, 1, ATTR_LEN_SIZE, infp) != ATTR_LEN_SIZE) {
					fprintf(UCRYPT_STDERR,
							"\nFrame Read Error: ATTR_LEN missing or invalid");
					ucrypt_log_error(35);
					return FALSE;

				}

				if (load16(buff, &attrib_len) == TRUE) {
					if ((attrib_len == 0) || (attrib_len > ATTR_MAX_LEN)) {
						fprintf(UCRYPT_STDERR,
								"\nFrame Read Error: Invalid ATTR_LEN");
						return FALSE;
					}
					/* read attrib_len no. of bytes*/
					if (fread(buffer, 1, attrib_len, infp) != attrib_len) {
						/* print it here */
						fprintf(UCRYPT_STDERR,
								"\nFrame Read Error: ATTR_DATA missing or invalid");
						ucrypt_log_error(35);
						return FALSE;
					}
					if (attrib_code == 4) {
						fprintf(UCRYPT_STDERR, "\n%10d\t%10d\t\tIV_DATA",
								attrib_code, attrib_len);
					} else if(attrib_code == 5)
						fprintf(UCRYPT_STDERR, "\n%10d\t%10d\t\tHMAC_DATA",
								attrib_code, attrib_len);
					else
						fprintf(UCRYPT_STDERR, "\n%10d\t%10d\t\t%s",
								attrib_code, attrib_len,buffer);
				}
				break;
			}
		}
	}
	return TRUE;
}

UCRYPT_BOOL attach_closing_frame(FILE *outfp) {
	/*we will attach 2 bytes of : attr_code 0 and
	 * 2 bytes for attr_len :00
	 */
	_uchar buff[4];
	memset(buff, 0, 4);
	if (store16(buff, 0) == TRUE) {
		/*write it*/
		if (fwrite(buff, 1, ATTR_CODE_SIZE, outfp) != ATTR_CODE_SIZE) {
			fprintf(UCRYPT_STDERR, "\nFailed to write frame markers.");
			return FALSE;
		}
	}
	memset(buff, 0, 4);
	if (store16(buff, 0) == TRUE) {
		/*write it*/
		if (fwrite(buff, 1, ATTR_LEN_SIZE, outfp) != ATTR_LEN_SIZE) {
			fprintf(UCRYPT_STDERR, "\nFailed to write frame markers.");
			return FALSE;
		}
	}
	return TRUE;
}
/*encode and decode for base64 routines */
/* ======================================================== */
/*use order :
 build_decoding_table()
 base64_encode()
 base64_decode()
 base64_cleanup
 */

//static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
//    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
//    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
//    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
//    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
//    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
//    'w', 'x', 'y', 'z', '0', '1', '2', '3',
//    '4', '5', '6', '7', '8', '9', '+', '/'};
//static char *decoding_table = NULL;
//static int mod_table[] = {0, 2, 1};
//
///*base64 encode and decode routines are also available in library so change names
// or remove them */
//char *base64_encode_l(const char *data,
//        size_t input_length,
//        size_t *output_length) {
//
//    *output_length = (size_t) (4.0 * ceil((double) input_length / 3.0));
//    _uint16 i, j;
//    char *encoded_data = malloc(*output_length);
//    if (encoded_data == NULL) return NULL;
//
//    for (i = 0, j = 0; i < input_length;) {
//
//        uint32_t octet_a = i < input_length ? data[i++] : 0;
//        uint32_t octet_b = i < input_length ? data[i++] : 0;
//        uint32_t octet_c = i < input_length ? data[i++] : 0;
//
//        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
//
//        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
//        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
//        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
//        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
//    }
//
//    for (i = 0; i < mod_table[input_length % 3]; i++)
//        encoded_data[*output_length - 1 - i] = '=';
//
//    return encoded_data;
//}
//
//char *base64_decode_l(const char *data,
//        size_t input_length,
//        size_t *output_length) {
//    _uint16 i, j;
//    if (decoding_table == NULL) build_decoding_table();
//
//    if (input_length % 4 != 0) return NULL;
//
//    *output_length = input_length / 4 * 3;
//    if (data[input_length - 1] == '=') (*output_length)--;
//    if (data[input_length - 2] == '=') (*output_length)--;
//
//    char *decoded_data = malloc(*output_length);
//    if (decoded_data == NULL) return NULL;
//
//    for (i = 0, j = 0; i < input_length;) {
//
//        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
//        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
//        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
//        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
//
//        uint32_t triple = (sextet_a << 3 * 6)
//                + (sextet_b << 2 * 6)
//                + (sextet_c << 1 * 6)
//                + (sextet_d << 0 * 6);
//
//        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
//        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
//        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
//    }
//
//    return decoded_data;
//}
//
//void build_decoding_table() {
//    _uint16 i;
//    decoding_table = malloc(256);
//
//    for (i = 0; i < 0x40; i++)
//        decoding_table[encoding_table[i]] = i;
//}
//
//void base64_cleanup() {
//    free(decoding_table);
//}
/* ======================================================== */
/*a automatic file closing code
 * struct FileOpen{
 FileOpen(FILE &* f, const char * name, const char * mode){
 f = fopen(name, mode);
 fp = f;
 }
 ~FileOpen(void){
 if (fp) fclose(fp);
 }
 FILE * fp;
 };

 FILE * myfile;
 FileOpen fo(myfile, "c:\\test.txt", "w");
 if (!myfile) return;
 */

UCRYPT_BOOL log_init(logger *l) {
	/*fname is ignored if mode is MODE_CONS or MODE_SYSLOG
	 * priority cant be greater than 7
	 * log.priority=log.priority & 0x07
	 */
	switch (l->mode) {
	case MODE_CONS:
		break;
	case MODE_SYSLOG:
		/*open syslog : ident,log_opt,fac*/
		openlog(l->prog_name, LOGGER_OPT, LOGGER_FAC);
		break;
	case MODE_FILE:
		/*try to open file*/
		if ((l->fp = fopen(l->fname, "a+b")) == NULL) {
			perror(l->prog_name);
			return FALSE;
		}
		break;
	default:
		/*if an invalid mode then use syslog*/
		l->mode = MODE_SYSLOG;
		break;
	}
	/*only extrem case of error such as direcory or file not writeble will be reported as FATAL
	 * and log_init() will fail
	 */
	return TRUE;
}
//a single parameter only
void log_msg(logger l, const char*msg) {
	/*ready the output string */

	time_t the_time;
	char time_buff[256], hostname[256];
	int len = 0;
	gethostname(hostname, 256);
	(void) time(&the_time);
	strncpy(time_buff, ctime(&the_time), 255);
	/*overwrite the newline marker attached with ctime() returnred string */
	len = strlen(time_buff);
	time_buff[len - 1] = '\0';
	switch (l.mode) {
	case MODE_CONS:
		fprintf(stderr, "%s %s[%d] @ %s: %s\n", time_buff, l.prog_name, l.pid,
				hostname, msg);
		break;
	case MODE_FILE:
		fprintf(l.fp, "%s %s[%d] @ %s: %s\n", time_buff, l.prog_name, l.pid,
				hostname, msg);
		break;
	default:
		/*default is MODE_SYSLOG*/
		syslog(l.priority, "%s:", msg);
		break;
	}
}
void close_log(logger l) {
	switch (l.mode) {
	case MODE_CONS:
		/*nothing special but we dont use closelog() in this mode so special case -not same as of MODE_SYSLOG*/
		break;
	case MODE_FILE:
		/*close file descriptor*/
		fclose(l.fp);
		break;
	default:
		/*MODE_SYSLOG is handled here */
		closelog();
		break;
	}
}
/*
 * logger log;
 strcpy(log.prog_name,"logger_test");
 log.mode=MODE_FILE;
 log.priority=LOG_INFO; //any one out of seven
 strcpy(log.fname,"test.log");
 log.pid=getpid();
 if(log_init(&log)==FALSE){
 sdebug("log_init:FAILED");
 return EXIT_FAILURE;
 }
 log_msg(log,"starting up");
 close_log(log);
 return EXIT_SUCCESS;

 */
