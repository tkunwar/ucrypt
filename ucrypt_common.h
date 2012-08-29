/* 
 * File:   ucrypt_common.h
 * Created on February 4, 2012, 10:40 AM
 */
#ifndef __UCRYPT_COMMON_H__
#define __UCRYPT_COMMON_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <syslog.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <math.h>
#include <stdint.h>
#include <error.h>
#include <errno.h>
#include <iconv.h> // iconv stuff
#include <langinfo.h> // nl_langinfo
#include <termios.h> // tcgetattr,tcsetattr


#include "ucrypt_error.h"
#include "ucrypt_version.h"
#include "crypt-headers/tomcrypt.h"
#include "ucrypt_password.h"
#include "ucrypt_config.h"
#define TRUE 1
#define FALSE 0
/*
 * some platform independent stuff
 * we will use ILP32 data models only for better portability across both 32
 * bit and 64 bit systems
 * and also across both MS-WIN and UNIX* systems
 * so use these data types throughout ucrypt
 * basically three sizes 16bit ,32 bit,64 bits
 * TODO: --write a pure 64 bit code later on (truly cross platform code
 * later on)
 *
 * Note : In ILP32 data model following assumptions hold true or must hold true.
 * sizeof(unsigned short int) : 2 Bytes --  _uint16
 * sizeof(unsigend long long int) : 8 bytes -- _uint64
 * sizeof(unsigned long int) : 4 bytes -- _uint32
 */
#define _int16 short int
#define _int32 long int
#define _int64 long long int
#define _uint16 unsigned short int
#define _uint32 unsigned long int
#define _uint64 unsigned long long int
#define _uchar unsigned char

#ifndef UCRYPT_BOOL
#define UCRYPT_BOOL _int16
#endif
#ifndef UCRYPT_ERR
#define UCRYPT_ERR _int16
#endif

#define FILE_PATH_LEN 1024 
#define MAX_PASSPHRASE_LEN 32
#define CRYPT_ALGO_LEN 100
#define PROG_NAME_LEN 100
#define VERSION_STR_LEN 50
#define MAX_IV_LEN 16  /*No algorithm uses an IV greater than 16 chars*/
#define MAX_KEY_LEN 32
#define CRYPT_BUFF_SIZE 512 /*size of buffer for encrypting and decrypting */
#define HMAC_BUFF_SIZE 32 /*in bytes using sha256 (needed only 32 bytes )*/
UCRYPT_BOOL file_exists(char *file);
/*a note for load and store functions:
 *
 * storeN() functions store unsigned N bit number to a location pointed by
 * buff.These store funtions take 2 arguments :pointer to buffer,and the N
 * bit number.
 * In each case size of buffer should be large enough  to store a N bit no.
 * this storage requirement is :
 *          for 16 bit no. : 2 bytes
 *          for 32 bit no. : 4 bytes
 *          for 64 bit no. : 8 bytes
 * These functions will store num in buffer and return TRUE if everything
 * was ok. However if buffer size is smaller than expected size a FALSE is
 * returned.
 *
 * About loadN() functions :
 * These functions will load a N bit no. from byte storage in a memory area
 * pointed by buff. Again a TRUE will be returned if required no. of bytes
 * were loaded from buffer else FALSE will be returned
 */
void store16(_uchar *buff, _uint16 num);
void load16(_uchar *buff, _uint16 *num);
void store32(_uchar *buff, _uint32 num);
void load32(_uchar *buff, _uint32 *num);
void store64(_uchar *buff, _uint64 num);
void load64(_uchar *buff, _uint64 *num);
void load_store_test();

#define ATTR_CODE_SIZE sizeof(unsigned short int)
#define ATTR_LEN_SIZE sizeof(unsigned short int)
#define MAX_PAYLOAD_SIZE sizeof(unsigned long long int)
#define MAX_ATTR_LEN_SIZE sizeof(unsigned long long int)
#define ATTR_BUFF_LEN 1024 //size of attribute attribute loaded

/*
 * the algorithm notifiers
 */
typedef enum {
        AES=1, BLOWFISH, CAST
} crypt_algo_t;

// actions ucrypt can perform
typedef enum{UNINIT, ENCRYPT, DECRYPT,ANALYZE,HELP,VERSION} ucrypt_actions_t;

//attribute codes -- reserved ones
typedef enum{ATTR_END,ATTR_PAYLOAD,ATTR_HEADER,ATTR_FILE_FORMAT,
				ATTR_IV,ATTR_HMAC,ATTR_PROG_NAME,ATTR_VERSION,
				ATTR_CRYPT_ALGO} reserved_attr_codes_t;

typedef struct {
	/*
	 * EDIT: it's inefficient to use an extra byte to identify data type of an
	 * attribute. We can use it to identify an attribute if it's an integer and
	 * can be packed but how we do we identify the same when we are reading
	 * from file. To do this ,we would need to store this bit as well. Moreover
	 * it could simply not look consistent. So we better leave it to user. Now
	 * we write a string and return a string only. Byte packing will be done
	 * only for attr_code and attr_len;
	 */
	_uint16 attr_code; /* support max. 65535 codes with each having length max.
	 	 	 	 	 	 65535 bytes
	 	 	 	 	 	 */
	_uint16 attr_len;
	const unsigned char *attr; /* some compliers will report (gcc does) about
	 	 	 	 	 	 	 	 size mismatch if u have declared attr as
	 	 	 	 	 	 	 	 char attr[SOME_CONSTANT] so better use
	 	 	 	 	 	 	 	 const char *attr */
} file_frame;

/* there does not seem to be an effective way of determining the frame_array
 * element count so necessarily for routines like getopt_long() user must
 * provide the last frame info as 0,0,0,NULL. it wont be written but will be
 * used for detecting the end of frame array
 */

/* write the frame_array to the stream pointed by outfp . Also ensure the byte
 * level packing passing array size is important as there is no real way of
 * determining its size. though getting last array element as 0,0,0,NULL is ok
 * but is more easy to miss rather than passing the size of array
 */
_uint16 file_frame_write(file_frame frame_array[],
		 _uint16 frame_array_size,FILE *outfp);

//read from input stream the attribute demanded based on the attr_code
UCRYPT_ERR file_frame_get_attr(_uint16 attr_code, _uint16 *attr_len,
		unsigned char *attr, FILE *infp);

/* this routine will simple scan the input stream from begining and print the
 * frame data for e.g it could print something like :
 * Frame code       Frame Length(Bytes)    Attribute
 * 2                3   		            XMP
 * 3                2           		    2
 * 4                8             		 xmpcrypt
 * 1             2323467          		 Payload
 */
UCRYPT_ERR file_frame_raw_scan(FILE *infp);

//returns file size in bytes
_uint64 get_file_size(FILE *infp);

//write the end of frame_array marker
UCRYPT_ERR attach_closing_frame(FILE *outfp);

/*base64 encode and decode routines */
char *base64_encode_l(const char *data, size_t input_length,
		size_t *output_length);
char *base64_decode_l(const char *data, size_t input_length,
		size_t *output_length);
void build_decoding_table();
void base64_cleanup();

// =========logging related variables and routines=========

/*define logger facility : possible values :
 * LOG_AUTH  LOG_AUTHPRIV  LOG_CRON  LOG_DAEMON LOG_FTP LOG_KERN
 * LOG_LPR LOG_MAIL  LOG_NEWS LOG_SYSLOG  LOG_USER  LOG_UUCP
 */
#define LOGGER_FAC LOG_USER

/* define logger option:possible values
 *LOG_PID LOG_CONS LOG_ODELAY LOG_NDELAY LOG_NOWAIT LOG_PERROR
 */
#define LOGGER_OPT (LOG_PERROR | LOG_PID | LOG_CONS)

#ifdef log_debug
/* lets make use of variadic macros
 * sdebug() macro is when we want to use single string message with no param
 * var_debug() macro can take multiple macros. Note that these are features of
 * C99 only if no C99 support then use long and clumsy debug macros--we are not
 * mentioning them here..have a look at debug.h
 *
 * Note : in case macros are using variable params and the respective macro
 * control flag is set to off then there will be warning messages about
 * variables not being used. This is ok.
 */
#ifdef _HAVE_LOGGER_C99_
#define sdebug(s) fprintf(stderr, "\n[" __FILE__ ":%i] debug: " s "",__LINE__)
#define var_debug(s, ...) fprintf(stderr, "\n[" __FILE__ ":%i] debug: " s "" ,\
	__LINE__,__VA_ARGS__)
#endif
#else
#define sdebug(s)
#define var_debug(s, ...)
#endif
/*now handle warning messages */
#ifndef _LOGGER_NO_WARNING_
#ifdef _HAVE_LOGGER_C99_
#define swarn(s) fprintf(stderr, "[" __FILE__ ":%i] Warning: " s "\n",__LINE__)
#define var_warn(s, ...) fprintf(stderr, "[" __FILE__ ":%i] Warning: " s "\n",\
		__LINE__,__VA_ARGS__)
#endif
#else
#define swarn(s)
#define var_warn(s, ...)
#endif
/*handle error messages as well*/
#ifndef _LOGGER_NO_ERR_
#ifdef _HAVE_LOGGER_C99_
#define serror(s) fprintf(stderr, "[" __FILE__ ":%i] Error: " s "\n",__LINE__)
#define var_error(s, ...) fprintf(stderr, "[" __FILE__ ":%i] Error: " s "\n",\
		__LINE__,__VA_ARGS__)
#endif
#else
#define serror(s)
#define var_error(s, ...)
#endif
#ifndef _LOGGER_NO_ERETURN_
#ifdef _HAVE_LOGGER_C99_
#define s_ereturn(rv, s) do{ fprintf(stderr, "[" __FILE__ ":%i] ereturn: " s \
		"\n", __LINE__); return rv; }while(0)
#define var_ereturn(rv, s,...) do{ fprintf(stderr, "[" __FILE__ ":%i] \
		ereturn: " s "\n", __LINE__,__VA_ARGS__); return rv; }while(0)
#endif
#else
#define s_ereturn(rv,s) return(rv)
#define var_ereturn(rv,s, ...) return(rv)
#endif

#define MAX_PROG_NAME 200

/*
 * logging modes :
 * MODE_CONS : log to console only
 * MODE_SYSLOG :log using syslog
 * MODE_FILE: log using custom log file
 * priority levels in decreasing level : LOG_EMERG,LOG_ALERT,LOG_CRIT,
 * 							LOG_ERR,LOG_WARNING,LOG_NOTICE,LOG_INFO,LOG_DEBUG
 */
typedef enum {
	MODE_CONS, MODE_SYSLOG, MODE_FILE
} log_mod_t;
typedef struct {
	char prog_name[MAX_PROG_NAME];
	log_mod_t mode;
	FILE *fp;_uint16 priority; //only seven priorities _uint16 should be enough
	pid_t pid;
	char fname[FILE_PATH_LEN];
} logger;

//initialize a logger object
UCRYPT_ERR log_init(logger *l);

/*
 * passing logger objects ensures that code will be safe from any modification
 * (thread-safe ??)
 * but cant i do without it ?
 */
void log_msg(logger l, const char*msg);

// modify logger's priority
UCRYPT_ERR set_logmask(logger *l, _uint16 UPTO_PRIO);

//we are done close the logger object
void close_log(logger l);

#ifdef	__cplusplus
}
#endif
#endif	/* UCRYPT_COMMON_H */
