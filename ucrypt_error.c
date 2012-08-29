/*
 * ucrypt_error.c
 */
#include "ucrypt_common.h"

/*
 * @@ucrypt_log_error()
 * Description: Prints the error messages. It takes an error code and prints
 * 				its equivalent error string.
 */
void ucrypt_log_error(unsigned int error_code) {
	/*
	 * TODO: cant we pass multiple parapeters(variable) to ucrypt_log_error()
	 * the error code is a mandatory parameter but others are optional
	 */
	fprintf(UCRYPT_STDERR, "\n%s: *Error*: ", PROG_NAME);
	switch (error_code) {
	case UCRYPT_ERR_INVALID_ARGS:
		fprintf(UCRYPT_STDERR, "Arguments supplied are not in proper form.");
		break;
	case UCRYPT_ERR_INVALID_COMMAND:
		fprintf(UCRYPT_STDERR, "No action defined (use with --encrypt|"
				"--decrypt|--analyze|--help|--version).");
		break;
	case UCRYPT_ERR_PATH_LIMIT:
		fprintf(UCRYPT_STDERR, "Output file name too long.");
		break;
	case UCRYPT_ERR_FILE_CREATE:
		fprintf(UCRYPT_STDERR, "Failed to create file.");
		break;
	case UCRYPT_ERR_TTY:
		fprintf(UCRYPT_STDERR, "Failed to access tty.");
		break;
	case UCRYPT_ERR_FILE_OPEN:
		fprintf(UCRYPT_STDERR, "Failed to open file.");
		break;
	case UCRYPT_ERR_FILE_READ:
		fprintf(UCRYPT_STDERR, "Failed to read data from file.");
		break;
	case UCRYPT_ERR_FILE_WRITE:
		fprintf(UCRYPT_STDERR, "Failed to write data to file.");
		break;
	case UCRYPT_ERR_INVALID_ALGO:
		fprintf(UCRYPT_STDERR, "Failed to determine crypto algorithm.");
		break;
	case UCRYPT_ERR_IV_GEN:
		fprintf(UCRYPT_STDERR, "IV generation failed.");
		break;
	case UCRYPT_ERR_IV_LOAD:
		fprintf(UCRYPT_STDERR, "Failed to load IV.");
		break;
	case UCRYPT_ERR_KEY_GEN:
		fprintf(UCRYPT_STDERR, "Key generation failed.");
		break;
	case UCRYPT_ERR_HEADER_GEN:
		fprintf(UCRYPT_STDERR, "Failed to write header.");
		break;
	case UCRYPT_ERR_HEADER_READ:
		fprintf(UCRYPT_STDERR, "Failed to read header.");
		break;
	case UCRYPT_ERR_VERSION_INCOMPAT:
		fprintf(UCRYPT_STDERR, "Incompatible file.");
		break;
	case UCRYPT_ERR_CRYPT:
		fprintf(UCRYPT_STDERR, "An error occurred in the encryption process.");
		break;
	case UCRYPT_ERR_DCRYPT:
		fprintf(UCRYPT_STDERR, "An error occurred in the decryption process.");
		break;
	case UCRYPT_ERR_ATTR_LOAD:
		fprintf(UCRYPT_STDERR, "Could not read value for attribute.");
		break;
	case UCRYPT_ERR_HMAC_ATTACH:
		fprintf(UCRYPT_STDERR, "Failed to write HMAC.");
		break;
	case UCRYPT_ERR_HMAC_VERIFY:
		fprintf(UCRYPT_STDERR, "HMAC verification failed.");
		break;
	case UCRYPT_ERR_PASSWD_READ:
		fprintf(UCRYPT_STDERR, "Could not read password.");
		break;
	case UCRYPT_ERR_FRAME_READ:
		fprintf(UCRYPT_STDERR, "Failed to read frame.");
		break;
	case UCRYPT_ERR_ATTR_INVALID_CODE:
		fprintf(UCRYPT_STDERR,
				"Frame Read Error: ATTR_CODE missing or invalid.");
		break;
	case UCRYPT_ERR_ATTR_INVALID_LEN:
		fprintf(UCRYPT_STDERR,
				"Frame Read Error: ATTR_LEN missing or invalid.");
		break;
	case UCRYPT_ERR_ATTR_INVALID_DATA:
		fprintf(UCRYPT_STDERR,
				"Frame Read Error: ATTR_DATA missing or invalid.");
		break;
	case UCRYPT_ERR_FRAME_WRITE:
		fprintf(UCRYPT_STDERR, "Failed to write frame markers.");
		break;
	case UCRYPT_ERR_LOG_INIT:
		fprintf(UCRYPT_STDERR, "Failed to initialize logger interface.");
		break;
	case UCRYPT_ERR_MEM:
		fprintf(UCRYPT_STDERR, "Failed to allocate memory.");
		break;
	case UCRYPT_ERR_INVALID_JOBQ:
		fprintf(UCRYPT_STDERR, "No jobs to process or invalid job list.");
		break;
	case UCRYPT_ERR_GENERIC:
		fprintf(UCRYPT_STDERR, "An unhandled error occurred.");
		break;

	default:
		fprintf(UCRYPT_STDERR, "Undefined error code.");
		break;
	}
	fprintf(UCRYPT_STDERR, "(Error code:0x%x)", error_code);
}
