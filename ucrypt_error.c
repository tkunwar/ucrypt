/*
 * ucrypt_error.c
 * here we store error codes 
 */
#include "ucrypt_common.h"

/* use enums for this purpose , can avoid searching in the table*/
ucrypt_error_table ucrypt_err[] = {
		{ UCRYPT_ERR_INVALID_ARGS,"Arguments supplied are not in proper form ."
				" Use ucrypt --help to see options." },
		{ UCRYPT_ERR_INVALID_COMMAND,"No action defined (use with --encrypt|"
				"--decrypt|--analyze|--help|--version)" },
		{ UCRYPT_ERR_FILE_CREATE, "Failed to create output file."},
		{UCRYPT_ERR_FILE_OPEN,"Failed to open file."},
		{UCRYPT_ERR_IV_GEN,"Could not generate IV."},
		{ 30, "Output file already exists." },
		{ 31, "Failed to write header (XMP tag)." }, { 32,
				"Failed to write extension header (info_tag)" }, { 33,
				"Extension size too big (max. allowed 0xFF bytes)." }, { 34,
				"Target file does not exist." }, { 35,
				"Input file too short or unsupported file." },

		{ 40, "Key length must be greater than or equal to 128 bits." }, { 41,
				"Bad file header (not a supported file or is it corrupted?)" },
		{ 42, "File format unsupported.!!" }, { 43,
				"Could not load extension tag!!" }, { 44,
				"Extension header size mismatch" }, { 50,
				"Crypt algorithm is unsupported" }, { 51,
				"Provided key is not of proper length" }, { 52,
				"Provided IV is not of proper length" }, { 53,
				"Cyrpto Handler state not initialized.." }, { 54,
				"Failed to complete encryption.." }, { 55,
				"Failed to initialize CTR mode." }, { 56, "File read error" }, {
				57, "Crypt_error: Failed to write output stream" }, { 58,
				"Failed to complete decryption" }, { 59,
				"Crypt_error: Algorithm not supported!!(Invalid state?)" }, {
				60, "Failed to save HMAC" }, { 61,
				"File checksum error.(Hash mismatch)" } };
_uint16 ucrypt_err_size = sizeof(ucrypt_err) / sizeof(ucrypt_err[0]);

void ucrypt_log_error(unsigned int error_code) {
	fprintf(UCRYPT_STDERR,
			"\n%s  Version: %s.%s compiled :%s",
			PROG_NAME, PROG_VERSION_MAJOR, PROG_VERSION_MINOR, PROG_DATE);
	fprintf(UCRYPT_STDERR, "\nError : %s (Error_code=%d)",
			ucrypt_err[error_code].err_string, error_code);

}
