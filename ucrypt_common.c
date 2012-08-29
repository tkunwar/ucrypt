#include "ucrypt_common.h"

/* @@file_exists()
 * Description : check if file exists. if it exists return true else
 * 				return false
 */
UCRYPT_BOOL file_exists(char *filename) {
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
 */
_uint64 get_file_size(FILE *infp) {
	_uint64 file_size;
	rewind(infp);
	fseek(infp, 0, SEEK_END);
	file_size = ftell(infp);
	fseek(infp, 0, SEEK_SET);
	return file_size;
}
/*
 * @@store16()
 * Description: stores a 16 bit unsigned integer to a unsigned character buffer
 */
void store16(_uchar *buff, _uint16 num) {
	buff[0] = num >> 8 & 0x00FF;
	buff[1] = num & 0x00FF;
}

/*
 * @@load16()
 * Description: loads an 16 bit unsigned integer from a buffer where it's been
 * 				stored in a byte packed manner.
 */
void load16(_uchar *buff, _uint16 *num) {
	*num = 0x0000;
	*num = *num | (_uint16) buff[0];
	*num = (*num << 8) | (_uint16) buff[1];
}

/*
 * @@store32()
 * Description: stores a 32 bit unsigned integer into an unsigned character
 * 				buffer.
 */
void store32(_uchar *buff, _uint32 num) {
	buff[0] = (num >> 24) & 0x000000FF;
	buff[1] = (num >> 16) & 0x000000FF;
	buff[2] = (num >> 8) & 0x000000FF;
	buff[3] = (num) & 0x000000FF;
}

/*
 * @@load32()
 * Description: loads a 32 bit unsigned integer from a unsigned buffer
 */
void load32(_uchar *buff, _uint32 *num) {
	*num = 0x00000000;
	*num = *num | (_uint16) buff[0];
	*num = (*num << 8) | (_uint16) buff[1];
	*num = (*num << 8) | (_uint16) buff[2];
	*num = (*num << 8) | (_uint16) buff[3];
}

/*
 * @@store64()
 * Description : packs a 64 bit unsigned integer into a buffer of type
 * 				unsigned char
 */
void store64(_uchar *buff, _uint64 num) {
	buff[0] = (num >> 56) & 0x00000000000000FF;
	buff[1] = (num >> 48) & 0x00000000000000FF;
	buff[2] = (num >> 40) & 0x00000000000000FF;
	buff[3] = (num >> 32) & 0x00000000000000FF;
	buff[4] = (num >> 24) & 0x00000000000000FF;
	buff[5] = (num >> 16) & 0x00000000000000FF;
	buff[6] = (num >> 8) & 0x00000000000000FF;
	buff[7] = (num) & 0x00000000000000FF;
}

/*
 * @@laod64()
 * Description : converst a 64 bit unsigned integer packed into buffer back
 * 				to a 64 bit unsigned int
 */
void load64(_uchar *buff, _uint64 *num) {
	*num = 0x0000000000000000;
	*num = *num | (_uint16) buff[0];
	*num = (*num << 8) | (_uint16) buff[1];
	*num = (*num << 8) | (_uint16) buff[2];
	*num = (*num << 8) | (_uint16) buff[3];
	*num = (*num << 8) | (_uint16) buff[4];
	*num = (*num << 8) | (_uint16) buff[5];
	*num = (*num << 8) | (_uint16) buff[6];
	*num = (*num << 8) | (_uint16) buff[7];
}

/*
 * @@load_store_test()
 * Description : test whether laod and store routines work properly.
 */
void load_store_test() {
	_uint16 num1 = 49997, num2;
	_uint32 num3 = 4134967295, num4;
	_uint64 num5 = 1743674407360922161, num6;
	_uchar buff[MAX_ATTR_LEN_SIZE];
	fprintf(UCRYPT_STDOUT, "\nTesting for 16,32,64 bit load,store routines..");
	fprintf(UCRYPT_STDOUT, "\nTesting 16 bit store: num is: %d", num1);
	store16(buff, num1);
	fprintf(UCRYPT_STDOUT, "\n16 bit store: byte sequence :%d %d ...OK",
			buff[0], buff[1]);
	fprintf(UCRYPT_STDOUT, "\nTesting 16 bit load:");
	load16(buff, &num2);
	fprintf(UCRYPT_STDOUT, "\n16 bit load :");
	if (num1 == num2)
		fprintf(UCRYPT_STDOUT, "...OK");
	else
		fprintf(UCRYPT_STDOUT, "...FAILED");
	fprintf(UCRYPT_STDOUT, "\nTesting 32 bit store: num is: %ld", num3);
	store32(buff, num3);
	fprintf(UCRYPT_STDOUT, "\n32 bit store: byte sequence :%d %d %d %d ...OK",
			buff[0], buff[1], buff[3], buff[4]);
	fprintf(UCRYPT_STDOUT, "\nTesting 32 bit load:");
	load32(buff, &num4);
	fprintf(UCRYPT_STDOUT, "\n32 bit load :");
	if (num3 == num4)
		fprintf(UCRYPT_STDOUT, "...OK");
	else
		fprintf(UCRYPT_STDOUT, "...FAILED");
	fprintf(UCRYPT_STDOUT, "\nTesting 64 bit store: num is: %lld", num5);
	store64(buff, num5);
	fprintf(UCRYPT_STDOUT,
			"\n64 bit store: byte sequence :%d %d %d %d %d %d %d %d...OK",
			buff[0], buff[1], buff[2], buff[3], buff[4], buff[5], buff[6],
			buff[7]);
	fprintf(UCRYPT_STDOUT, "\nTesting 64 bit load:");
	load64(buff, &num6);
	fprintf(UCRYPT_STDOUT, "\n64 bit load :");
	if (num5 == num6)
		fprintf(UCRYPT_STDOUT, "...OK");
	else
		fprintf(UCRYPT_STDOUT, "...FAILED");
}

/*
 * @@file_frame_write()
 * Description : writes to outfp elements of frame_array of size
 * 				frame_array_size. But before doing so, it packs both attr_code
 * 				and attr_len fields of frame_array.
 */
_uint16 file_frame_write(file_frame frame_array[], _uint16 frame_array_size,
		FILE *outfp) {
	_uint16 i = 0;
	_uint16 frames_written = 0;
	_uchar attr_code[ATTR_CODE_SIZE];
	_uchar attr_len[ATTR_LEN_SIZE];
	for (i = 0; i < frame_array_size; i++) {
		memset(attr_code, 0, ATTR_CODE_SIZE);
		store16(attr_code, frame_array[i].attr_code);
		if (fwrite(attr_code, 1, ATTR_CODE_SIZE, outfp) != ATTR_CODE_SIZE) {
			return frames_written;
		}

		memset(attr_len, 0, ATTR_LEN_SIZE);
		store16(attr_len, frame_array[i].attr_len);
		if (fwrite(attr_len, 1, ATTR_LEN_SIZE, outfp) != ATTR_LEN_SIZE) {
			return frames_written;
		}

		if (fwrite(frame_array[i].attr, 1, frame_array[i].attr_len, outfp)
				!= frame_array[i].attr_len) {
			return frames_written;
		}
		frames_written++;
	}
	return frames_written;
}

/*
 * @@file_frame_get_attr()
 * Description: Reads value of an attribute identified by attr_code from a file
 * 				pointed to by infp and stores it to attr.
 */
UCRYPT_ERR file_frame_get_attr(_uint16 attr_code, _uint16 *attr_len,
		_uchar *attr, FILE *infp) {
	_uint16 attrib_code, attrib_len;
	_uchar buff[MAX_ATTR_LEN_SIZE];
	_uint64 payload_size = 0;
	rewind(infp);
	while (infp) {
		memset(buff, 0, MAX_ATTR_LEN_SIZE);
		if (fread(buff, 1, ATTR_CODE_SIZE, infp) != ATTR_CODE_SIZE) {
			ucrypt_log_error(UCRYPT_ERR_ATTR_INVALID_CODE);
			return UCRYPT_ERR_ATTR_INVALID_CODE;
		}

		load16(buff, &attrib_code);
		memset(buff, 0, MAX_ATTR_LEN_SIZE); //reset buff
		switch (attrib_code) {
		case ATTR_END:
			return UCRYPT_ERR_GENERIC;
		case ATTR_PAYLOAD:
			if (fread(buff, 1, MAX_PAYLOAD_SIZE, infp) != MAX_PAYLOAD_SIZE) {
				ucrypt_log_error(UCRYPT_ERR_ATTR_INVALID_LEN);
				return UCRYPT_ERR_ATTR_INVALID_LEN;
			}
			load64(buff, &payload_size);
			fseek(infp, payload_size, SEEK_CUR);
			break;
		default:
			if (fread(buff, 1, ATTR_LEN_SIZE, infp) != ATTR_LEN_SIZE) {
				ucrypt_log_error(UCRYPT_ERR_ATTR_INVALID_LEN);
				return UCRYPT_ERR_ATTR_INVALID_LEN;
			}

			load16(buff, &attrib_len);
			if ((attrib_len == 0) || (attrib_len > ATTR_BUFF_LEN)) {
				ucrypt_log_error(UCRYPT_ERR_ATTR_INVALID_LEN);
				return UCRYPT_ERR_ATTR_INVALID_LEN;
			}

			if (attrib_code == attr_code) {
				memset(attr, 0, attrib_len);
				if (fread(attr, 1, attrib_len, infp) != attrib_len) {
					ucrypt_log_error(UCRYPT_ERR_ATTR_INVALID_DATA);
					return UCRYPT_ERR_ATTR_INVALID_DATA;
				}
				*attr_len = attrib_len;
				return UCRYPT_OK;
			} else
				fseek(infp, attrib_len, SEEK_CUR);
			break;
		}
	}
	return UCRYPT_ERR_GENERIC;
}
/*
 * @@file_frame_raw_scan()
 * Description: Prints a simple scan of a ucrypt encrypted file, showing
 * 			attributes and their content if possible.
 */
UCRYPT_ERR file_frame_raw_scan(FILE *infp) {
	_uint16 attrib_code, attrib_len;
	unsigned char buff[MAX_ATTR_LEN_SIZE];
	_uint64 file_size;
	char buffer[ATTR_BUFF_LEN];
	sdebug(
			"Dumping raw scan data :\n\tATTR_CODE  ATTR_LEN(in bytes)\tATTR_DATA"
			"\n\t---------  ------------\t\t------------\n");
	rewind(infp);
	while (infp) {
		memset(buff, 0, MAX_ATTR_LEN_SIZE);
		memset(buffer, 0, ATTR_BUFF_LEN);
		if (fread(buff, 1, ATTR_CODE_SIZE, infp) != ATTR_CODE_SIZE) {
			ucrypt_log_error(UCRYPT_ERR_ATTR_INVALID_CODE);
			return UCRYPT_ERR_ATTR_INVALID_CODE;
		}
		load16(buff, &attrib_code);
		switch (attrib_code) {
		case ATTR_END:
			memset(buff, 0, MAX_ATTR_LEN_SIZE);
			if (fread(buff, 1, ATTR_LEN_SIZE, infp) != ATTR_LEN_SIZE) {
				ucrypt_log_error(UCRYPT_ERR_ATTR_INVALID_LEN);
				return UCRYPT_ERR_ATTR_INVALID_LEN;
			}

			load16(buff, &attrib_len);
			if ((attrib_len == 0)) {
				fprintf(UCRYPT_STDERR, "\n\tEOF\t\tEOF");
				return UCRYPT_OK;
			}
			break;
		case ATTR_PAYLOAD:
			memset(buff, 0, MAX_PAYLOAD_SIZE);
			if (fread(buff, 1, MAX_PAYLOAD_SIZE, infp) != MAX_PAYLOAD_SIZE) {
				ucrypt_log_error(UCRYPT_ERR_ATTR_INVALID_LEN);
				return UCRYPT_ERR_ATTR_INVALID_LEN;
			}
			load64(buff, &file_size);
			fprintf(UCRYPT_STDERR, "\n\t1\t%10llu\t\tPAYLOAD_DATA", file_size);
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
			if (fread(buffer, 1, attrib_len, infp) != attrib_len) {
				ucrypt_log_error(UCRYPT_ERR_ATTR_INVALID_DATA);
				return UCRYPT_ERR_ATTR_INVALID_DATA;
			}
			if (attrib_code == ATTR_IV) {
				fprintf(UCRYPT_STDERR, "\n%10d\t%10d\t\tIV_DATA", attrib_code,
						attrib_len);
			} else if (attrib_code == ATTR_HMAC)
				fprintf(UCRYPT_STDERR, "\n%10d\t%10d\t\tHMAC_DATA", attrib_code,
						attrib_len);
			else
				fprintf(UCRYPT_STDERR, "\n%10d\t%10d\t\t%s", attrib_code,
						attrib_len, buffer);
			break;
		}
	}
	return UCRYPT_OK;
}

/*
 * @@attach_closing_frame()
 * Description: write out the closing frame-- means no more writing to the file.
 * 				write 2 bytes for attr_code "0" and 2 bytes for attr_len "0"
 */
UCRYPT_ERR attach_closing_frame(FILE *outfp) {
	_uchar buff[MAX_ATTR_LEN_SIZE]; //used for byte packing
	memset(buff, 0, MAX_ATTR_LEN_SIZE);
	store16(buff, ATTR_END);
	if (fwrite(buff, 1, ATTR_CODE_SIZE, outfp) != ATTR_CODE_SIZE) {
		ucrypt_log_error(UCRYPT_ERR_FRAME_WRITE);
		return UCRYPT_ERR_FRAME_WRITE;
	}
	memset(buff, 0, MAX_ATTR_LEN_SIZE);
	store16(buff, 0);
	if (fwrite(buff, 1, ATTR_LEN_SIZE, outfp) != ATTR_LEN_SIZE) {
		ucrypt_log_error(UCRYPT_ERR_FRAME_WRITE);
		return UCRYPT_ERR_FRAME_WRITE;
	}
	return UCRYPT_OK;
}

/*
 * @@log_init()
 * Description: initialize a logger instance.
 * 				fname is ignored if mode is MODE_CONS or MODE_SYSLOG.
 */
UCRYPT_ERR log_init(logger *l) {
	switch (l->mode) {
	case MODE_CONS:
		break;
	case MODE_SYSLOG:
		/*open syslog : ident,log_opt,fac*/
		openlog(l->prog_name, LOGGER_OPT, LOGGER_FAC);
		break;
	case MODE_FILE:
		if ((l->fp = fopen(l->fname, "a+b")) == NULL) {
			perror(l->prog_name);
			ucrypt_log_error(UCRYPT_ERR_LOG_INIT);
			return UCRYPT_ERR_LOG_INIT;
		}
		break;
	default:
		/*if an invalid mode then use syslog*/
		l->mode = MODE_SYSLOG;
		break;
	}
	return UCRYPT_OK;
}

/*
 * @@log_msg()
 * Description : log the message as specifies by the instance.
 */
void log_msg(logger l, const char*msg) {
	time_t the_time;
	char time_buff[256], hostname[256];
	int len = 0;
	gethostname(hostname, 256);
	(void) time(&the_time);
	strncpy(time_buff, ctime(&the_time), 255);

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

/*
 * @@close_log()
 * Description : closes the logger instance.
 */
void close_log(logger l) {
	switch (l.mode) {
	case MODE_CONS:
		/* nothing special but we dont use closelog() in this mode so
		 * special case -not same as of MODE_SYSLOG*/
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

/*//sample code on how to use logger.
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
