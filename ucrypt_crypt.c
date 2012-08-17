/*
 * ucrypt_crypt.c
 * main source file for ucrypt
 */
#include "ucrypt_common.h"
#include "ucrypt_crypt.h"
#include "ucrypt_crypt_handler.h"

/*
 * we have two ways of logging information
 * 1. using an object of logger
 * 2. using macros sdebug,swarn,serror or var_debug,var_warn,var_error
 *  (using macros for their simplicity)
 */

//the default action is UNINIT
ucrypt_actions_t action = UNINIT;

error_codes_t err = UCRYPT_OK;
/*function prototypes*/
UCRYPT_ERR generate_header(FILE *outfp);
UCRYPT_BOOL encrypt_main(FILE *infp, FILE *outfp);
UCRYPT_BOOL decrypt_main(FILE *infp, FILE *outfp);
UCRYPT_ERR process_args(int argc, char *argv[]);
void init_crypt_args();
UCRYPT_ERR check_if_ucrypt_args_populated();
void dump_args();
void print_usage();
void print_version();
void cleanup(const char *src_file);
UCRYPT_BOOL create_iv();
UCRYPT_BOOL create_key();
void set_iv_size();
void set_key_size();
UCRYPT_ERR get_password();
UCRYPT_ERR set_crypt_algo(char *optarg);

int main(int argc, char *argv[]) {

	FILE *infp, *outfp = NULL;
	//extension_header exthdr;
	_uint64 file_size=0;
	if (process_args(argc, argv) == UCRYPT_ERR_INVALID_ARGS) {
		return UCRYPT_ERR_INVALID_ARGS;
	}

	switch (action) {
	case ENCRYPT:
		if (strcmp(ucrypt_args.out_file, "") == 0) {
			if (strlen(ucrypt_args.src_file) >= (FILE_PATH_LEN - 4)) {
				/*
				 * there is no room to create output file by appending ".uff"
				 * to the src_file
				 */
				ucrypt_log_error(UCRYPT_ERR_FILE_CREATE);
				return UCRYPT_ERR_FILE_CREATE;
			}
			strcpy(ucrypt_args.out_file, ucrypt_args.src_file);
			strncat(ucrypt_args.out_file, ".uff", 4);
		}
		outfp = fopen(ucrypt_args.out_file, "wb");
		if (!outfp) {
			ucrypt_log_error(UCRYPT_ERR_FILE_OPEN);
			return UCRYPT_ERR_FILE_OPEN;
		}

		/*steps :
		 * generate header and write it and finally pass the pointer to encryption routine
		 */
		if (generate_header(outfp) != UCRYPT_OK) {
			/*An error in header generation occurred abort*/
			fclose(outfp);
			cleanup(ucrypt_args.out_file);
			return UCRYPT_ERR_HEADER_GEN;
		}
		/*now we call our main encryption routine which will do some checks and also
		 * perform encryption
		 */
		infp = fopen(ucrypt_args.src_file, "rb");
		if (!infp) {
			var_error("Failed to open file %s", ucrypt_args.src_file);
			fclose(infp);
			cleanup(ucrypt_args.out_file);
			return UCRYPT_ERR_FILE_OPEN;
		}

		if (encrypt_main(infp, outfp) != UCRYPT_OK) {
			fclose(infp);
			fclose(outfp);
			cleanup(ucrypt_args.out_file);
			return UCRYPT_ERR_CRYPT;
		}
		/*before closing in we write the file close markers.*/
		if (attach_closing_frame(outfp) == FALSE) {
			var_error("Failed to close output file %s", ucrypt_args.src_file);
			fclose(outfp);
			fclose(infp);
			cleanup(ucrypt_args.out_file);
			return UCRYPT_ERR_FILE_OPEN;
		}
		fclose(outfp);
		fclose(infp);
		break;
	case DECRYPT:
		sdebug("Action is to decrypt file ..");
		outfp = fopen(ucrypt_args.out_file, "wb");
		if (!outfp) {
			var_error("Failed to open file %s", ucrypt_args.out_file);
			fclose(outfp);
			cleanup(ucrypt_args.out_file);
			return UCRYPT_ERR_FILE_OPEN;
		}
		infp = fopen(ucrypt_args.src_file, "rb");
		if (!infp) {
			var_error("Failed to open file %s", ucrypt_args.src_file);
			fclose(infp);
			cleanup(ucrypt_args.out_file);
			return UCRYPT_ERR_FILE_OPEN;
		}
		if (decrypt_main(infp, outfp) != UCRYPT_OK) {
			fclose(outfp);
			cleanup(ucrypt_args.out_file);
			return UCRYPT_ERR_CRYPT;
		}

		fclose(outfp);
		fclose(infp);
		break;
	case ANALYZE:
		var_debug("Prepairing to analyze file : %s", ucrypt_args.src_file);
		infp = fopen(ucrypt_args.src_file, "rb");
		if (!infp) {
			var_error("Failed to open file %s", ucrypt_args.src_file);
			fclose(infp);
			return UCRYPT_ERR_FILE_OPEN;
		}
		crypt_handler_get_payload_info(infp, &file_size);
		var_debug("Actual payload size: %llu bytes", file_size);

		if (file_frame_raw_scan(infp) == FALSE) {
			serror("Failed to complete frame scaning..(Bad file ?)");
			return UCRYPT_ERR_HEADER_READ;
		}
		fclose(infp);
		break;
	case HELP:
		print_usage();
		break;
	case VERSION:
		print_version();
		break;
	default:
		serror("Invalid primary mode !!");
		break;
	}

	return EXIT_SUCCESS;
}

UCRYPT_ERR generate_header(FILE *outfp) {
	/* these frame_codes are reserved
	 * 0=end_markers ,  1=payload_marker,
	 * 2=program_header,3=file_format_version,
	 * 4=iv,			5,=hmac
	 * 6=PROG_NAME		7=PRG_VERSION_STRING
	 * 8=crypt_algo
	 */
	_uint16 frames_written = 0;
	char crypt_algo[CRYPT_ALGO_LEN];
	switch(ucrypt_args.crypt_algo){
	case BLOWFISH:
		sprintf(crypt_algo, "%s", "blowfish");
		break;
	case CAST:
		sprintf(crypt_algo, "%s", "cast");
		break;
	default :
		sprintf(crypt_algo, "%s", "aes");
		break;
	}
	//1. make IV
	if (create_iv() != TRUE) {
		serror("Failed to create IV for encryption");
		return UCRYPT_ERR_IV_GEN;
	}
	sdebug("In generate_header():\nPrepairing to write header frames");
	//by this time we must have iv and iv len
	file_frame frame_array[] = {
			{ 2, strlen(FILE_FORMAT_HEADER_TAG), (_uchar *)"UFF" },
			{ 3, strlen(FILE_FORMAT_VERSION),(_uchar*) FILE_FORMAT_VERSION },
			{ 4, ucrypt_args.iv_len, ucrypt_args.iv }, //cant use strlen
			{ 6, strlen(PROG_NAME),(_uchar*) PROG_NAME },
			{ 7, strlen(PROG_VERSION_STRING), (_uchar*)PROG_VERSION_STRING },
			{ 8, strlen(crypt_algo),(_uchar*) (crypt_algo) },

	/*{0,0,0,NULL} :it wont be written to file but will be used as a marker
	 * to detect end of frame_array. not needed any more
	 */
	};
	if ((frames_written = file_frame_write(frame_array,
			sizeof(frame_array) / sizeof(frame_array[0]), outfp)) != 0) {
		var_debug("No. of frames written: %d", frames_written);
	} else {
		serror("frame write failed");
		return UCRYPT_ERR_HEADER_GEN;
	}
	return UCRYPT_OK;
}

UCRYPT_ERR encrypt_main(FILE *infp, FILE *outfp) {

	crypt_handler_state state;

	//2. make key from IV and passphrase
	if(create_key() != TRUE){
		serror("Failed to create Key for encryption");
		return UCRYPT_ERR_KEY_GEN;
	}

	//3. initialize crypt_handler_state
	crypt_handler_init(&state, ucrypt_args.crypt_algo, ucrypt_args.key,
			ucrypt_args.key_len, ucrypt_args.iv, ucrypt_args.iv_len);
	//4. call encryption routine
	if (crypt_handler_encrypt(&state, infp, outfp) != UCRYPT_OK) {
		serror("Encryption failed !!");
		return UCRYPT_ERR_CRYPT;
	}
	sdebug("\nencrypt_main(): Encryption successfully completed..");
	return UCRYPT_OK;
}

UCRYPT_ERR decrypt_main(FILE *infp, FILE *outfp) {
	crypt_handler_state state;
	_uchar iv[MAX_IV_LEN];
	_uchar crypt_algo_name[50];

	_uint16 attrlen;
	memset(iv, 0, MAX_IV_LEN); //reset IV
	//1. load IV from file
	//TODO : IV is not being loaded properly
	if (file_frame_get_attr(4, &attrlen,iv, infp) != TRUE) {
		fprintf(UCRYPT_STDERR, "\nFailed to load Initialization Vector ");
		return UCRYPT_ERR_IV_GEN;
	}
	/*
	 * Note that the loaded IV length may vary due to version differences.
	 * Therefore, though ucrypt_args.iv_len is already set in process_args,
	 * we will overwrite it with the iv length
	 */
	ucrypt_args.iv_len = attrlen;
	memcpy(ucrypt_args.iv,iv,ucrypt_args.iv_len);

	//2. load crypt_algo from file and update necessary info in ucrypt_args
	if (file_frame_get_attr(8, &attrlen,crypt_algo_name, infp) != TRUE) {
			fprintf(UCRYPT_STDERR, "\nFailed to determine crypt_algo used");
			return UCRYPT_ERR_ATTR_LOAD;
	}
	//ensure that crypt_algo_name is a proper char string
	crypt_algo_name[attrlen]='\0';
	//set crypt_algo and associated fields in ucrypt_args
	if(set_crypt_algo((char *)crypt_algo_name) != UCRYPT_OK)
		return UCRYPT_ERR_DCRYPT;

	rewind(infp);
	//3. create key from passphrase and IV
	if(create_key()!=TRUE){
			serror("Failed to create Key for encryption");
			return UCRYPT_ERR_KEY_GEN;
	}

	//4. init the crypt_handler_state
	crypt_handler_init(&state, ucrypt_args.crypt_algo, ucrypt_args.key,
			ucrypt_args.key_len, ucrypt_args.iv, ucrypt_args.iv_len);

	//5. call the decryption routine
	if (crypt_handler_decrypt(&state, infp, outfp) != UCRYPT_OK) {
		serror("Failed to decrypt file");
		return UCRYPT_ERR_DCRYPT;
	}
	sdebug("decrypt_main(): Decryption successfully completed..");

	return UCRYPT_OK;
}

UCRYPT_ERR process_args(int argc, char *argv[]) {
	/*
	 * output file name is optional, if provided will be used else, a new file
	 * of name type <filename>.ucf will be generated in the current directory
	 */
	_int16 opt_retval;
	struct option longopts[] = { { "debug", 0, NULL, 'D' }, { "analyze", 0,
			NULL, 'a' }, { "version", 0, NULL, 'v' }, { "help", 0, NULL, 'h' },
			{ "encrypt", 0, NULL, 'e' }, { "decrypt", 0, NULL, 'd' }, {
					"src_file", 1, NULL, 'f' }, { "out_file", 1, NULL, 'o' }, {
					"crypt_algo", 1, NULL, 'c' }, { "pass", 1, NULL, 'p' },
					{ 0, 0, 0, 0 } };

	/*call init_crypt_args to reset everything **/
	init_crypt_args();
	while ((opt_retval = getopt_long(argc, argv, "avhedc:o:f:p:", longopts,
			NULL)) != -1) {
		switch (opt_retval) {
		case 'a':
			/*
			 * encrypt and decrypt action have privilege over analyze, help and
			 * other commands.
			 */
			if (action != ENCRYPT || action != DECRYPT)
				action = ANALYZE;
			break;
		case 'v':
			if (action != ENCRYPT || action != DECRYPT) {
				action = VERSION;
			}
			break;
		case 'h':
			if (action != ENCRYPT || action != DECRYPT) {
				action = HELP;
			}
			break;
		case 'e':
			/*
			 * no matter which command has been passed , if among commands
			 * passed there is encrypt, then this will be preferred.
			 */
			action = ENCRYPT;
			break;
		case 'd':
			action = DECRYPT;
			break;
		case 'f':
			/*
			 * file name must be greater than zero but less than FILE_PATH_LEN
			 */
			if (strlen(optarg) == 0) {
				serror("Missing source file name !!!");
				return UCRYPT_ERR_INVALID_ARGS;
			}

			if (strlen(optarg) > FILE_PATH_LEN - 1) {
				var_error("Size of src_file must be less than %d",
						FILE_PATH_LEN - 1);
				return UCRYPT_ERR_INVALID_ARGS;
			} else
				strncpy(ucrypt_args.src_file, optarg, FILE_PATH_LEN);
			break;
		case ':':
			if (UCRYPT_DEBUG)
				fprintf(UCRYPT_STDERR, "\n Option needs a value ");
			break;
		case 'o':
			if (strlen(optarg) == 0) {
				serror("Missing output file name !!!");
				return UCRYPT_ERR_INVALID_ARGS;
			}
			if (strlen(optarg) > FILE_PATH_LEN - 1) {
				var_error("Size of out_file must be less than %d",
						FILE_PATH_LEN - 1);
				return UCRYPT_ERR_INVALID_ARGS;
			} else
				strncpy(ucrypt_args.out_file, optarg, FILE_PATH_LEN);
			break;
		case 'c':
			if (set_crypt_algo(optarg) != UCRYPT_OK)
				return UCRYPT_ERR_INVALID_ARGS;
			break;
		case 'p':
			if (optarg != 0) {
				ucrypt_args.pass_len = passwd_to_utf16(optarg,
						strlen((char *) optarg), MAX_PASSPHRASE_LEN + 1,
						ucrypt_args.passphrase);

				if (ucrypt_args.pass_len < 0) {
					serror("Password length too short");
					return UCRYPT_ERR_INVALID_ARGS;
				}
			}
			break;

		case '?':
			if (UCRYPT_DEBUG)
				fprintf(UCRYPT_STDERR, "\nUnknown option %c", optopt);
			break;
		}
	}
	/*rest of options can be treated as arguments
	 */
	for (; optind < argc; optind++) {
		var_debug("argument: %s ", argv[optind]);
	}
	//if no parameter was passed print the program usage

	if (argc == 1) {
		ucrypt_log_error(UCRYPT_ERR_INVALID_ARGS);
		print_usage();
		return UCRYPT_ERR_INVALID_ARGS;
	}
	/*verify if action was either encrypt,decrypt or analyze or any other
	 * but defined
	 */
	if (action == UNINIT) {
		ucrypt_log_error(UCRYPT_ERR_INVALID_COMMAND);
		return UCRYPT_ERR_INVALID_ARGS;
	}

	if (check_if_ucrypt_args_populated() != UCRYPT_OK) {
		serror("Value for one or more arguments is missing or is invalid");
		return UCRYPT_ERR_INVALID_ARGS;
	} else {
		ucrypt_args.args_ok = TRUE;
	}
	return UCRYPT_OK;
}
UCRYPT_ERR set_crypt_algo(char *optarg){
	int algo_set = FALSE;
	if ((strncmp(optarg, "aes", CRYPT_ALGO_LEN - 1) == 0)
						|| (strncmp(optarg, "AES", CRYPT_ALGO_LEN - 1) == 0)) {
					ucrypt_args.crypt_algo = AES;
					algo_set = TRUE;
	}
	if ((strncmp(optarg, "blowfish", CRYPT_ALGO_LEN - 1) == 0)
						|| (strncmp(optarg, "BLOWFISH", CRYPT_ALGO_LEN - 1) == 0)) {
					ucrypt_args.crypt_algo = BLOWFISH;
					algo_set = TRUE;
	}
	if ((strncmp(optarg, "cast", CRYPT_ALGO_LEN - 1) == 0)
						|| (strncmp(optarg, "CAST", CRYPT_ALGO_LEN - 1) == 0)) {
					ucrypt_args.crypt_algo = CAST;
					algo_set = TRUE;
	}
	if(algo_set != TRUE)
		return UCRYPT_ERR_INVALID_ARGS;
	//set IV size according to crypt_algo
	set_iv_size();
	//set key size according to crypt_algo
	set_key_size();
	return UCRYPT_OK;
}
/*
 * @@init_crypt_args()
 *	Description : Initializes ucrypt_args with default values (if applicable)
 *	Default values:
 *		default_algo : AES-256
 *		IV len : 16 bytes (size of block)
 */
void init_crypt_args() {
	ucrypt_args.args_ok = FALSE;
	//strcpy(ucrypt_args.crypt_algo, "AES");
	ucrypt_args.crypt_algo = AES;
	strcpy(ucrypt_args.passphrase, "");
	strcpy(ucrypt_args.out_file, "");
	strcpy(ucrypt_args.src_file, "");
	ucrypt_args.iv_len = 16;
	memset(ucrypt_args.iv, 0, MAX_IV_LEN);
}

/* check if any parameter has not been loaded . if it's the case set the
 * args_populated to false else true
 * and also return UCRYPT_ERR_INVALID_ARGS
 */UCRYPT_ERR check_if_ucrypt_args_populated() {
	switch (action) {
	case ENCRYPT:
		if (strcmp(ucrypt_args.passphrase, "") == 0) {
			swarn("Passphrase missing...Enter it now..");
			if (get_password() != UCRYPT_OK)
				return UCRYPT_ERR_INVALID_ARGS;
		}
		if (strcmp(ucrypt_args.src_file, "") == 0) {
			serror("Missing source file name");
			return UCRYPT_ERR_INVALID_ARGS;
		}
		if (strcmp(ucrypt_args.out_file, "") == 0) {
			serror("Missing output file name");
			return UCRYPT_ERR_INVALID_ARGS;
		}
		var_debug("crypt_algo: %d",ucrypt_args.crypt_algo);
		//crypt algo must be one of aes|AES|blowfish|BLOWFISH|cast|CAST
		if ((ucrypt_args.crypt_algo != AES) && (ucrypt_args.crypt_algo != BLOWFISH)
				&& (ucrypt_args.crypt_algo != CAST)) {
			serror("Invalid crypto algorithm selected");
			return UCRYPT_ERR_INVALID_ARGS;
		}
		break;
	case ANALYZE:
		if (strcmp(ucrypt_args.src_file, "") == 0) {
			serror("Missing source file !!");
			return UCRYPT_ERR_INVALID_ARGS;
		}
		break;
	case DECRYPT:
		if (strcmp(ucrypt_args.passphrase, "") == 0) {
			serror("Missing passphrase !!");
			if (get_password() != UCRYPT_OK)
				return UCRYPT_ERR_INVALID_ARGS;
		}
		if (strcmp(ucrypt_args.src_file, "") == 0) {
			serror("Missing source file name!!");
			return UCRYPT_ERR_INVALID_ARGS;
		}
		if (strcmp(ucrypt_args.out_file, "") == 0) {
			serror("Missing output file name");
			return UCRYPT_ERR_INVALID_ARGS;
		}
		break;
	default:
		swarn("Undefined action !!!");
		break;
	}
	return UCRYPT_OK;
}

void dump_args() {
	fprintf(UCRYPT_STDOUT, "\n");
	fprintf(UCRYPT_STDOUT, "\n\n--------This is what i have-------");
	fprintf(UCRYPT_STDOUT, "\nAction: %d", action);
	fprintf(UCRYPT_STDOUT, "\nSource file: %s", ucrypt_args.src_file);
	fprintf(UCRYPT_STDOUT, "\nOutput file: %s", ucrypt_args.out_file);
	fprintf(UCRYPT_STDOUT, "\nAlgorithm Selected: %d", ucrypt_args.crypt_algo);
	fprintf(UCRYPT_STDOUT, "\nPassphrase (Remove it): %s",
			ucrypt_args.passphrase);
}

/*
 * prints the usage of ucrypt_crypt
 */
void print_usage() {

	fprintf(UCRYPT_STDOUT, "\n\nUsage: %s <commands> <argument1> <argument2>..",
			PROG_NAME);
	fprintf(UCRYPT_STDOUT,
			"\n%s encrypts,decrypts or analyzes the native encrypted files. ",
			PROG_NAME);
	fprintf(UCRYPT_STDOUT, "\n----Commandline description :----");
	fprintf(UCRYPT_STDOUT,
			"\nA command can be of two types..one which takes arguments while other does not..");
	fprintf(UCRYPT_STDOUT, "\nThose who do not require any argument are: ");
	fprintf(UCRYPT_STDOUT, "\n\t-v, --version\t\tPrint version of %s",
			PROG_NAME);
	fprintf(UCRYPT_STDOUT, "\n\t-h, --help\t\tPrints help options");
	fprintf(UCRYPT_STDOUT,
			"\n\t-e, --encrypt\t\tEncrypts the given source file along with some arguments");
	fprintf(UCRYPT_STDOUT,
			"\n\t-d, --decrypt\t\tDecrypts the given source file along with some arguments");
	fprintf(UCRYPT_STDOUT,
			"\n\t-a, --analyze\t\tAnalyze the given file and print its header info");

	fprintf(UCRYPT_STDOUT, "\n\nFolowing commands take mandatory arguments..");
	fprintf(UCRYPT_STDOUT,
			"\n\tThese arguments (for --encrypt command) are as :");
	fprintf(UCRYPT_STDOUT,
			"\n\t\t-f, --src_file\t\tSource file that is to be encrypted.");
	fprintf(UCRYPT_STDOUT, "\n\t\t-o, --src_file\t\tName of the output file.");
	fprintf(UCRYPT_STDOUT,
			"\n\t\t-c, --crypt_algo\tCryptographic algorithm to be used");
	fprintf(UCRYPT_STDOUT, "\n\t\t-p, --pass\t\tPassword used in encryption");
	fprintf(UCRYPT_STDOUT,
			"\n\nFor e.g.\nucrypt --encrypt --src_file=<source_file> --out_file=<output_file>"
			" --crypt_algo=<aes|blowfish|cast> -pass=<password> \n\n");

}

/*
 * prints version of ucrypt_crypt
 */
void print_version() {
	fprintf(UCRYPT_STDOUT, "\n%s Version: %s.%s compiled :%s\n", PROG_NAME,
			PROG_VERSION_MAJOR, PROG_VERSION_MINOR, PROG_DATE);
}

void cleanup(const char *src_file) {
	if (unlink(src_file) == -1) {
		fprintf(UCRYPT_STDERR, "\nFailed to perform cleanup");
		/*return EXIT_FAILURE;*/
	}
}

/*
 * @@get_iv()
 * Description: generates iv of len specified by ucrypt_args.iv_len and saves it
 * 				to ucrypt_args.iv
 */
UCRYPT_BOOL create_iv() {
	FILE *randfp = NULL;
	hash_state md;
	unsigned char buffer[32];
	unsigned char digest[32]; //temporary storage for hashed rand data
	int i;
	time_t current_time;
	pid_t process_id;

	// Open the source for random data.  Note that while the entropy
	// might be lower with /dev/urandom than /dev/random, it will not
	// fail to produce something.  Also, we're going to hash the result
	// anyway.
	if ((randfp = fopen("/dev/urandom", "r")) == NULL) {
		perror("Error opening /dev/urandom:");
		return FALSE;
	}
	//register hash
	if (register_hash(&sha256_desc) == -1) {
		serror("Error registering sha256");
		return FALSE;
	}

	// We will use an initialization vector (16 bytes)comprised of the current
	//time ,process ID, and random data, all hashed together with SHA-256.
	//buffer has first octet of time and other from process_id
	memset(buffer, 0, 32);
	current_time = time(NULL);
	for (i = 0; i < 8; i++) {
		buffer[i] = (unsigned char) (current_time >> (i * 8));
	}
	process_id = getpid();
	for (i = 0; i < 8; i++) {
		buffer[i + 8] = (unsigned char) (process_id >> (i * 8));
	}

	sha256_init(&md);
	sha256_process(&md, buffer, 16);

	for (i = 0; i < 256; i++) {
		if (fread(buffer, 1, 32, randfp) != 32) {
			serror("Couldn't read from /dev/urandom");
			fclose(randfp);
			return FALSE;
		}
		sha256_process(&md, buffer, 32);
	}

	sha256_done(&md, digest);
	//now depending upon the algorithm use the IV
	memcpy(ucrypt_args.iv, digest, ucrypt_args.iv_len);
	// We're finished collecting random data
	fclose(randfp);
	return TRUE;
}

/*
 * @@create_key()
 * Description: creates a proper size key based on the passphrase entered by
 * 				user
 */
UCRYPT_BOOL create_key() {
	//key is obtained by hashing IV and password 8192 times
	hash_state md;
	unsigned char digest[32];
	int i;
	//register hash
		if (register_hash(&sha256_desc) == -1) {
			serror("Error registering sha256");
			return FALSE;
		}

		//reset digest and key
	    memset(digest, 0, 32);
	    memset(ucrypt_args.key,0,ucrypt_args.key_len);
	    //copy iv to digest
	    memcpy(digest, ucrypt_args.iv, ucrypt_args.iv_len);
	    // Hash the IV and password 8192 times
	    for(i=0; i<8192; i++)
	    {
	    	sha256_init(&md);
	        sha256_process(  &md, digest, 32);
	        sha256_process(  &md,
	                        (unsigned char*)ucrypt_args.passphrase,
	                        ucrypt_args.pass_len);
	        sha256_done(  &md,digest);
	    }
	    //though the digest is of 256 bits but we take only what we need
	    memcpy(ucrypt_args.key,digest,ucrypt_args.key_len);
	return TRUE;
}
/*
 * @@get_iv_size()
 * Description :Sets the size of iv for a crypto algorithm in
 * 				ucrypt_args.iv_len.
 */
void set_iv_size() {
	switch (ucrypt_args.crypt_algo) {
	case BLOWFISH:
		ucrypt_args.iv_len = 8;
		break;
	case CAST:
		ucrypt_args.iv_len = 8;
		break;
	case AES:
	default:
		//default is AES only
		ucrypt_args.iv_len = 16;
		break;
	}
}
void set_key_size() {
	switch (ucrypt_args.crypt_algo) {
	case BLOWFISH:
		ucrypt_args.key_len = 32;
		break;
	case CAST:
		ucrypt_args.key_len = 16;
		break;
	case AES:
	default:
		//default is AES only
		ucrypt_args.key_len = 32;
		break;
	}
}
UCRYPT_ERR get_password() {

	char input_pass[MAX_PASSPHRASE_LEN + 1];
	int input_pass_len;
	input_pass_len = read_password(input_pass);

	switch (input_pass_len) {
	case 0: //no password in input
		fprintf(stderr, "Error: No password supplied.\n");
		cleanup(ucrypt_args.out_file);
		return UCRYPT_ERR_PASSWD_READ;
	case AESCRYPT_READPWD_FOPEN:
	case AESCRYPT_READPWD_FILENO:
	case AESCRYPT_READPWD_TCGETATTR:
	case AESCRYPT_READPWD_TCSETATTR:
	case AESCRYPT_READPWD_FGETC:
	case AESCRYPT_READPWD_TOOLONG:
		fprintf(stderr, "Error in read_password: %s.\n",
				read_password_error(ucrypt_args.pass_len));
		cleanup(ucrypt_args.out_file);
		return UCRYPT_ERR_PASSWD_READ;
	case AESCRYPT_READPWD_NOMATCH:
		fprintf(stderr, "Error: Passwords don't match.\n");
		cleanup(ucrypt_args.out_file);
		return UCRYPT_ERR_PASSWD_READ;
	}
	//convert the input_password to ensure UTF-16 compatibility
	ucrypt_args.pass_len = passwd_to_utf16(input_pass, input_pass_len,
			MAX_PASSPHRASE_LEN + 1, ucrypt_args.passphrase);
	if (ucrypt_args.pass_len < 0) {
		cleanup(ucrypt_args.out_file);
		// For security reasons, erase the password
		memset(input_pass, 0, input_pass_len);
		return UCRYPT_ERR_PASSWD_READ;
	}
	return UCRYPT_OK;
}
