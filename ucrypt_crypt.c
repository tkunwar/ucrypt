/*
 * ucrypt_crypt.c
 * main source file for ucrypt
 */
#include "ucrypt_common.h"
#include "ucrypt_crypt.h"
#include "ucrypt_crypt_handler.h"

error_codes_t err = UCRYPT_OK;
struct UCRYPT_STATE ucrypt_state; //global state

int main(int argc, char *argv[]) {
	UCRYPT_ERR uc_error;

	//init the state
	init_ucrypt_state();

	//process arguments recieved
	if (process_args(argc, argv) == UCRYPT_ERR_INVALID_ARGS) {
		return UCRYPT_ERR_INVALID_ARGS;
	}
	//call job manager
	if ((uc_error = job_manager()) != UCRYPT_OK) {
		return uc_error;
	}
	return EXIT_SUCCESS;
}
/*
 * @@init_crypt_state()
 * Description: Initializes various attributes in ucrypt_state.
 */
void init_ucrypt_state() {
	//initialize our state before we do anything
	ucrypt_state.job_q = NULL;
	ucrypt_state.job_length = 0;
	ucrypt_state.batch_mode = FALSE;
	ucrypt_state.skipped_jobs = 0;

	//also init the global settings
	ucrypt_state.global_settings.action = UNINIT;
	ucrypt_state.global_settings.crypt_algo = AES;
	ucrypt_state.global_settings.pass_len = 0;
	strcpy(ucrypt_state.global_settings.passphrase, "");
}
/*
 * @@process_args()
 * Description: processes arguments and parameters passed to ucrypt.
 */
UCRYPT_ERR process_args(int argc, char *argv[]) {
	struct job_desc_t job;
	_int16 opt_retval;
	struct option longopts[] = { { "debug", 0, NULL, 'D' }, { "analyze", 0,
			NULL, 'a' }, { "version", 0, NULL, 'v' }, { "help", 0, NULL, 'h' },
			{ "encrypt", 0, NULL, 'e' }, { "decrypt", 0, NULL, 'd' }, {
					"crypt_algo", 1, NULL, 'c' }, { "pass", 1, NULL, 'p' }, {
					"batch", 1, NULL, 'b' }, { 0, 0, 0, 0 } };

	while ((opt_retval = getopt_long(argc, argv, "avhedc:p:", longopts, NULL))
			!= -1) {
		switch (opt_retval) {
		case 'a':
			/*
			 * encrypt and decrypt action have privilege over analyze, help and
			 * other commands.
			 */
			if (ucrypt_state.global_settings.action != ENCRYPT
					|| ucrypt_state.global_settings.action != DECRYPT)
				ucrypt_state.global_settings.action = ANALYZE;
			break;
		case 'v':
			if (ucrypt_state.global_settings.action != ENCRYPT
					|| ucrypt_state.global_settings.action != DECRYPT) {
				ucrypt_state.global_settings.action = VERSION;
			}
			break;
		case 'h':
			if (ucrypt_state.global_settings.action != ENCRYPT
					|| ucrypt_state.global_settings.action != DECRYPT) {
				ucrypt_state.global_settings.action = HELP;
			}
			break;
		case 'e':
			/*
			 * no matter which command has been passed , if among commands
			 * passed there is encrypt/decrypt, then this will be preferred.
			 */
			ucrypt_state.global_settings.action = ENCRYPT;
			break;
		case 'd':
			ucrypt_state.global_settings.action = DECRYPT;
			break;

		case ':':
			sdebug("Option needs a value ");
			break;
		case 'b':
			load_job_from_file(optarg);
			break;
		case 'c':
			if ((ucrypt_state.global_settings.crypt_algo = set_crypt_algo(
					optarg)) == UCRYPT_ERR_GENERIC)
				return UCRYPT_ERR_INVALID_ARGS;
			break;
		case 'p':
			if (optarg != 0) {
				ucrypt_state.global_settings.pass_len = strlen(optarg);
				strncpy(ucrypt_state.global_settings.passphrase, optarg,
						MAX_PASSPHRASE_LEN);
				if (ucrypt_state.global_settings.pass_len < 8) {
					ucrypt_log_error(UCRYPT_ERR_INVALID_ARGS);
					return UCRYPT_ERR_INVALID_ARGS;
				}
			}
			break;

		case '?':
			var_debug("\nUnknown option %c", optopt);
			break;
		}
	}
	//all the following processing is valid only in non-batch mode
	if (ucrypt_state.batch_mode == FALSE) {
		for (; optind < argc; optind++) {
			job.file_path[0] = '\0';
			strncpy(job.file_path, argv[optind], FILE_PATH_LEN - 1);
			if (enqueue_job(&job) != UCRYPT_OK)
				return UCRYPT_ERR_INVALID_ARGS;
		}
		//if no parameter was passed print the program usage
		if (argc == 1) {
			ucrypt_log_error(UCRYPT_ERR_INVALID_ARGS);
			print_usage();
			return UCRYPT_ERR_INVALID_ARGS;
		}
		/* verify if action was either encrypt,decrypt or analyze or any other
		 * but defined
		 */
		if (ucrypt_state.global_settings.action == UNINIT) {
			ucrypt_log_error(UCRYPT_ERR_INVALID_COMMAND);
			return UCRYPT_ERR_INVALID_COMMAND;
		}

		if (check_if_ucrypt_args_populated() != UCRYPT_OK) {
			ucrypt_log_error(UCRYPT_ERR_INVALID_ARGS);
			return UCRYPT_ERR_INVALID_ARGS;
		}
	}
	return UCRYPT_OK;
}
/*
 * @@enqueue_job(struct job_desc_t *job)
 * Description: This routine recives pointer to a job type. As we are in
 * 				non-batch mode so we are concerned with field job->file_path
 * 				only. This object will be added to queue ucrypt_state.job_q .
 */UCRYPT_ERR enqueue_job(struct job_desc_t *job) {
	struct job_queue *tempnode = NULL;
	if (ucrypt_state.job_q == NULL) {
		ucrypt_state.job_q = (struct job_queue*) malloc(
				sizeof(struct job_queue));
		if (!ucrypt_state.job_q)
			return UCRYPT_ERR_MEM;

		ucrypt_state.job_q->job = *job;
		ucrypt_state.job_q->next = NULL;
		ucrypt_state.last_queued_node = ucrypt_state.job_q;
	} else {
		tempnode = (struct job_queue*) malloc(sizeof(struct job_queue));
		if (!tempnode)
			return UCRYPT_ERR_MEM;
		tempnode->job = *job;
		tempnode->next = NULL;
		ucrypt_state.last_queued_node->next = tempnode;
		ucrypt_state.last_queued_node = tempnode;
	}
	ucrypt_state.job_length++;
	return UCRYPT_OK;
}

/*
 * @@job_manager()
 * Description : This is the master routine, which processes the job_queue.
 */
 UCRYPT_ERR job_manager() {
	FILE *infp, *outfp = NULL;
	_uint64 file_size = 0;
	struct job_desc_t job;
	char out_file[FILE_PATH_LEN];

	int job_state = FALSE;
	if (!ucrypt_state.job_q) {
		ucrypt_log_error(UCRYPT_ERR_INVALID_JOBQ);
		return UCRYPT_ERR_INVALID_JOBQ;
	}
//	print the enqueued jobs
//	sdebug("Queued jobs: ");
//	print_job_queue();
	while (1) {
		job = dequeue_job(&job_state);
		if (!job_state)
			break;
		var_debug("Processing file : %s", job.file_path);
		switch (job.action) {
		case ENCRYPT:
			strncpy(out_file, job.file_path, FILE_PATH_LEN);
			//check if output file name can be formed by appending ".uff"
			//extension
			if (strlen(out_file) >= FILE_PATH_LEN - 4) {
				skip_job(UCRYPT_ERR_PATH_LIMIT);
				continue; //skip anything further
			}
			strncat(out_file, ".uff", 4);

			infp = fopen(job.file_path, "rb");
			if (!infp) {
				skip_job(UCRYPT_ERR_FILE_OPEN);
				continue;
			}

			outfp = fopen(out_file, "wb");
			if (!outfp) {
				fclose(infp);
				skip_job(UCRYPT_ERR_FILE_OPEN);
				continue;
			}

			if (encrypt_main(infp, outfp, &job) != UCRYPT_OK) {
				fclose(outfp);
				cleanup(out_file);
				skip_job(UCRYPT_ERR_CRYPT);
			}

			//close all
			fclose(outfp);
			fclose(infp);
			break;
		case DECRYPT:
			// we are assuming ".uff" extension -- so strip 4 chars from
			// file_path to form out_file
			strncpy(out_file, job.file_path, FILE_PATH_LEN);
			out_file[strlen(job.file_path) - 4] = '\0';

			infp = fopen(job.file_path, "rb");
			if (!infp) {
				skip_job(UCRYPT_ERR_FILE_OPEN);
				continue;
			}

			outfp = fopen(out_file, "wb");
			if (!outfp) {
				skip_job(UCRYPT_ERR_FILE_OPEN);
				fclose(infp);
				continue;
			}

			if (decrypt_main(infp, outfp, &job) != UCRYPT_OK) {
				fclose(outfp);
				cleanup(out_file);
				skip_job(UCRYPT_ERR_DCRYPT);
			}

			fclose(outfp);
			fclose(infp);
			break;
		case ANALYZE:
			var_debug("Prepairing to analyze file : %s", job.file_path);
			infp = fopen(job.file_path, "rb");
			if (!infp) {
				ucrypt_log_error(UCRYPT_ERR_FILE_OPEN);
				continue;
			}
			crypt_handler_get_payload_info(infp, &file_size);
			var_debug("Actual payload size: %llu bytes", file_size);

			if (file_frame_raw_scan(infp) != UCRYPT_OK) {
				fclose(infp);
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
		fprintf(UCRYPT_STDERR, "\t..OK");
	}
	//print a summary of jobs handled
	fprintf(UCRYPT_STDERR, "\nTotal Jobs: %d", ucrypt_state.job_length);
	fprintf(UCRYPT_STDERR, " | Failed : %d | Successful : %d",
			ucrypt_state.skipped_jobs,
			(ucrypt_state.job_length - ucrypt_state.skipped_jobs));
	if (ucrypt_state.skipped_jobs > 0)
		return UCRYPT_ERR_JOB_PROCESS;
	return UCRYPT_OK;
}
/*
 * @@print_job_queue()
 * Description: Prints all the jobs queued for processing
 */
void print_job_queue() {
	struct job_queue *curnode = ucrypt_state.job_q;
	while (curnode) {
		fprintf(UCRYPT_STDERR, "\n%s", curnode->job.file_path);
		curnode = curnode->next;
	}
}
/*
 * @@skip_job(error_code)
 * Description: This routine recieves an error code and calls ucrypt_log_error
 * 				with same error code. Also icrements the skipped_jobs.
 */
void skip_job(UCRYPT_ERR err_code) {
	ucrypt_log_error(err_code);
	fprintf(UCRYPT_STDERR, " Operation skipped!!");
	ucrypt_state.skipped_jobs++;
}

/*
 * @@encrypt_main()
 * Description: The main encryption routine. Manages other subroutines
 */UCRYPT_ERR encrypt_main(FILE *infp, FILE *outfp, struct job_desc_t *job) {
	/*
	 * steps to follow:
	 * 1. generate iv
	 * 2. write out header
	 * 3. generate key
	 * 4. perform encryption
	 */
	crypt_handler_state state;
	unsigned char iv[MAX_IV_LEN];
	_uint16 iv_len;
	unsigned char key[MAX_KEY_LEN];
	_uint16 key_len;
	//1. create IV
	if (create_iv(job->crypt_algo, iv, &iv_len) != TRUE) {
		return UCRYPT_ERR_IV_GEN;
	}

	//2. write out header
	if (generate_header(outfp, job->crypt_algo, iv, iv_len) != UCRYPT_OK) {
		return UCRYPT_ERR_HEADER_GEN;
	}

	//3. make key from IV and passphrase
	if (create_key(job->crypt_algo, key, &key_len, iv, iv_len,
			job->passphrase) != TRUE) {
		ucrypt_log_error(UCRYPT_ERR_KEY_GEN);
		return UCRYPT_ERR_KEY_GEN;
	}

	//4. initialize crypt_handler_state
	crypt_handler_init(&state, job->crypt_algo, key, key_len, iv, iv_len);

	//5. call encryption routine
	if (crypt_handler_encrypt(&state, infp, outfp) != UCRYPT_OK) {
		ucrypt_log_error(UCRYPT_ERR_CRYPT);
		return UCRYPT_ERR_CRYPT;
	}

	//before closing in we write the file close markers.
	if (attach_closing_frame(outfp) != UCRYPT_OK) {
		ucrypt_log_error(UCRYPT_ERR_FILE_WRITE);
		return UCRYPT_ERR_FILE_WRITE;
	}
	return UCRYPT_OK;
}
/*
 * @@create_iv(crypt_algo_t algo,_uchar *iv,_uint16 *iv_len)
 * Description: generates iv and saves it to iv. Also modifies the iv_len
 * 				to indicate the size of iv generated in IV.
 */
 UCRYPT_BOOL create_iv(crypt_algo_t algo, _uchar *iv, _uint16 *iv_len) {
	FILE *randfp = NULL;
	hash_state md;
	unsigned char buffer[32];
	unsigned char digest[32]; //temporary storage for hashed rand data
	int i;
	time_t current_time;
	pid_t process_id;

	//determine iv_len
	*iv_len = get_iv_size(algo);

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
	// time ,process ID, and random data, all hashed together with SHA-256.
	// buffer has first octet of time and other from process_id
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

	memcpy(iv, digest, *iv_len);
	fclose(randfp);
	return TRUE;
}

/*
 *	@@generate_header():
 *	Description : given the required parameters and the output file pointer,
 *					this routine saves those parameters in the file.
 */
 UCRYPT_ERR generate_header(FILE *outfp, crypt_algo_t algo, _uchar *iv,
		_uint16 iv_len) {
	_uint16 frames_written = 0;
	char crypt_algo[CRYPT_ALGO_LEN];
	//determine the equivalent string names of the algorithm we are going
	//to use
	switch (algo) {
	case BLOWFISH:
		sprintf(crypt_algo, "%s", "blowfish");
		break;
	case CAST:
		sprintf(crypt_algo, "%s", "cast");
		break;
	default:
		sprintf(crypt_algo, "%s", "aes");
		break;
	}

	file_frame frame_array[] = { { ATTR_HEADER, strlen(FILE_FORMAT_HEADER_TAG),
			(_uchar *) "UFF" }, { ATTR_FILE_FORMAT, strlen(FILE_FORMAT_VERSION),
			(_uchar*) FILE_FORMAT_VERSION }, { ATTR_IV, iv_len, iv }, {
			ATTR_PROG_NAME, strlen(PROG_NAME), (_uchar*) PROG_NAME }, {
			ATTR_VERSION, strlen(PROG_VERSION_STRING),
			(_uchar*) PROG_VERSION_STRING }, { ATTR_CRYPT_ALGO, strlen(
			crypt_algo), (_uchar*) (crypt_algo) },

	/*{0,0,0,NULL} :it wont be written to file but will be used as a marker
	 * to detect end of frame_array. not needed any more
	 */
	};
	if ((frames_written = file_frame_write(frame_array,
			sizeof(frame_array) / sizeof(frame_array[0]), outfp)) != 0) {
	} else {
		ucrypt_log_error(UCRYPT_ERR_HEADER_GEN);
		return UCRYPT_ERR_HEADER_GEN;
	}
	return UCRYPT_OK;
}
/*
 * @@decrypt_main()
 * Description: The main routine for decrypting a file.
 */
 UCRYPT_ERR decrypt_main(FILE *infp, FILE *outfp, struct job_desc_t *job) {
	crypt_handler_state state;
	_uchar iv[MAX_IV_LEN];
	_uchar crypt_algo_name[50];
	_uint16 iv_len, attrlen, key_len;
	_uchar key[MAX_KEY_LEN];

	memset(iv, 0, MAX_IV_LEN); //reset IV

	//1. load IV from file
	if (file_frame_get_attr(ATTR_IV, &iv_len, iv, infp) != UCRYPT_OK) {
		ucrypt_log_error(UCRYPT_ERR_IV_LOAD);
		return UCRYPT_ERR_IV_LOAD;
	}

	//2. load crypt_algo from file
	if (file_frame_get_attr(ATTR_CRYPT_ALGO, &attrlen, crypt_algo_name,
			infp) != UCRYPT_OK) {
		ucrypt_log_error(UCRYPT_ERR_INVALID_ALGO);
		return UCRYPT_ERR_INVALID_ALGO;
	}
	//ensure that crypt_algo_name is a proper char string
	crypt_algo_name[attrlen] = '\0';
	rewind(infp);

	// we depend upon set_crypt_algo for provding us the algo id if a valid
	// name if provided to it else an error --as both are essentially integers.
	// Be warned-- never let a crypt_algo have an index as UCRYPT_ERR_GENERIC.

	if ((job->crypt_algo = set_crypt_algo((char *) crypt_algo_name))
			== UCRYPT_ERR_GENERIC)
		return UCRYPT_ERR_DCRYPT;

	//3. create key from passphrase and IV
	if (create_key(job->crypt_algo, key, &key_len, iv, iv_len,
			job->passphrase) != TRUE) {
		ucrypt_log_error(UCRYPT_ERR_KEY_GEN);
		return UCRYPT_ERR_KEY_GEN;
	}

	//4. init the crypt_handler_state
	crypt_handler_init(&state, job->crypt_algo, key, key_len, iv, iv_len);

	//5. call the decryption routine
	if (crypt_handler_decrypt(&state, infp, outfp) != UCRYPT_OK) {
		ucrypt_log_error(UCRYPT_ERR_DCRYPT);
		return UCRYPT_ERR_DCRYPT;
	}
	return UCRYPT_OK;
}

/*
 * @@dequeue_job()
 * Description: This routine returns a job from the queue by removing it
 * 				from ucrypt_state.job_q. It also sets job_state to true/false
 * 				depending upon whether we have any valid job or not. The caller
 * 				must not use a job if the job_state is false;
 */
struct job_desc_t dequeue_job(int *job_state) {
	struct job_queue headnode, *temp = NULL;
	*job_state = FALSE; //default
	if (ucrypt_state.job_q) {
		headnode = *ucrypt_state.job_q; //save first item
		temp = ucrypt_state.job_q; //will be freed
		ucrypt_state.job_q = ucrypt_state.job_q->next;
		free(temp);

		//now if we are in batch mode then headnode.job has every info in proper
		//form that will be needed by job_manager. However in non-batch mode,
		// only file_path is present, rest of values need to be looked from
		//global settings. So before returning the job ,we will ensure it has
		// proper fields
		check_job_state(&headnode.job);
		*job_state = TRUE;
	}
	return (headnode.job);
}

/*
 *	@@check_job_state()
 *	Description: This routine ensures that a given job object of type job_desc_t
 *				has proper values.
 */
void check_job_state(struct job_desc_t *job) {
	if (ucrypt_state.batch_mode == FALSE) {
		job->action = ucrypt_state.global_settings.action;
		job->crypt_algo = ucrypt_state.global_settings.crypt_algo;
		job->pass_len = ucrypt_state.global_settings.pass_len;
		strncpy(job->passphrase, ucrypt_state.global_settings.passphrase,
				MAX_PASSPHRASE_LEN);
	}
}

/*
 * @@load_job_from_file(char *batch_file_path)
 * Description : when run with --batch=batch_file_path, ucrypt will load
 * 				the job queue from this file. This routine loads the job_queue
 * 				in ucrypt_state.job_q. Also sets the use_global_settings to
 * 				false.
 */
UCRYPT_ERR load_job_from_file(char *batch_file_path) {
	ucrypt_state.batch_mode = TRUE;
	return UCRYPT_OK;
}

/*
 * @@set_crypt_algo(char *optarg)
 * Description : this routine checks if string optarg matches any identifiable
 * 				name for a supported crypto algo. It returns the algo else
 * 				UCRYPT_ERR_GENERIC.
 * Warning: Ensure that UCRYPT_ERR_GENERIC will never be same as a crypt_algo_t
 * value (both being enums).
 */
UCRYPT_ERR set_crypt_algo(char *optarg) {
	if ((strncmp(optarg, "aes", 3) == 0) || (strncmp(optarg, "AES", 3) == 0)) {
		return AES;

	} else if ((strncmp(optarg, "blowfish", 8) == 0)
			|| (strncmp(optarg, "BLOWFISH", 8) == 0)) {
		return BLOWFISH;
	} else if ((strncmp(optarg, "cast", 4) == 0)
			|| (strncmp(optarg, "CAST", 4) == 0)) {
		return CAST;
	}

	return UCRYPT_ERR_GENERIC;
}

/*
 * @@check_if_ucrypt_args_populated():
 * Description:  check if any parameter has not been loaded . if it's the
 * 				case set the  args_populated to false else true  and also
 * 				return UCRYPT_ERR_INVALID_ARGS.
 */
UCRYPT_ERR check_if_ucrypt_args_populated() {
	switch (ucrypt_state.global_settings.action) {
	case ENCRYPT:
		if (strcmp(ucrypt_state.global_settings.passphrase, "") == 0) {
			swarn("Passphrase missing...Enter it now..");
			if (get_password(ucrypt_state.global_settings.passphrase,
					&ucrypt_state.global_settings.pass_len) != UCRYPT_OK)
				return UCRYPT_ERR_INVALID_ARGS;
		}

		//crypt algo must be one of aes|AES|blowfish|BLOWFISH|cast|CAST
		if ((ucrypt_state.global_settings.crypt_algo != AES)
				&& (ucrypt_state.global_settings.crypt_algo != BLOWFISH)
				&& (ucrypt_state.global_settings.crypt_algo != CAST)) {
			ucrypt_log_error(UCRYPT_ERR_INVALID_ALGO);
			return UCRYPT_ERR_INVALID_ALGO;
		}
		break;
	case ANALYZE:
		//atleast one file must be provided
		break;
	case DECRYPT:
		if (strcmp(ucrypt_state.global_settings.passphrase, "") == 0) {
			if (get_password(ucrypt_state.global_settings.passphrase,
					&ucrypt_state.global_settings.pass_len) != UCRYPT_OK)
				return UCRYPT_ERR_INVALID_ARGS;
		}
		break;
	default:
		swarn("Undefined action !!!");
		break;
	}
	return UCRYPT_OK;
}

/*
 * @@print_usage():
 * Description: prints the usage of ucrypt.
 */
void print_usage() {

	fprintf(UCRYPT_STDOUT, "\n\nUsage: %s <commands> <argument1> <argument2>..",
			PROG_NAME);
	fprintf(UCRYPT_STDOUT,
			"\n%s encrypts,decrypts or analyzes the native encrypted files. ",
			PROG_NAME);
	fprintf(UCRYPT_STDOUT, "\n----Commandline description :----");
	fprintf(UCRYPT_STDOUT,
			"\nA command can be of two types..one which takes arguments while "
					"other does not..");
	fprintf(UCRYPT_STDOUT, "\nThose who do not require any argument are: ");
	fprintf(UCRYPT_STDOUT, "\n\t-v, --version\t\tPrint version of %s",
			PROG_NAME);
	fprintf(UCRYPT_STDOUT, "\n\t-h, --help\t\tPrints help options");
	fprintf(UCRYPT_STDOUT,
			"\n\t-e, --encrypt\t\tEncrypts the given source file along with"
					" some arguments");
	fprintf(UCRYPT_STDOUT,
			"\n\t-d, --decrypt\t\tDecrypts the given source file along with "
					"some arguments");
	fprintf(UCRYPT_STDOUT,
			"\n\t-a, --analyze\t\tAnalyze the given file and print its header"
					" info");

	fprintf(UCRYPT_STDOUT, "\n\nFolowing commands take mandatory arguments..");
	fprintf(UCRYPT_STDOUT,
			"\n\tThese arguments (for --encrypt command) are as :");
	fprintf(UCRYPT_STDOUT,
			"\n\t\t-c, --crypt_algo\tCryptographic algorithm to be used");
	fprintf(UCRYPT_STDOUT, "\n\t\t-p, --pass\t\tPassword used in encryption");
	fprintf(UCRYPT_STDOUT,
			"\n\nFor e.g.\nucrypt --encrypt --crypt_algo=<aes|blowfish|cast> "
					"-pass=<password> file1 file2 file3\n\n");
	fprintf(UCRYPT_STDOUT,
			"\nucrypt --decrypt file1.uff file2.uff file3.uff\n");
}

/*
 * @@print_version():
 * Description: prints version of ucrypt
 */
void print_version() {
	fprintf(UCRYPT_STDOUT, "\n%s Version: %s.%s compiled :%s\n", PROG_NAME,
			PROG_VERSION_MAJOR, PROG_VERSION_MINOR, PROG_DATE);
}

/*
 * @@cleanup():
 * Description: After a failed operation, removes any temprary files created.
 */
void cleanup(const char *src_file) {
	if (unlink(src_file) == -1) {
		fprintf(UCRYPT_STDERR, "\nFailed to perform cleanup");
		/*return EXIT_FAILURE;*/
	}
}

/*
 * @@create_key()
 * Description: creates a proper size key based on the passphrase entered by
 * 				user
 */UCRYPT_BOOL create_key(crypt_algo_t algo, _uchar *key, _uint16 *key_len,
		_uchar *iv, _uint16 iv_len, char *passphrase) {
	hash_state md;
	unsigned char digest[32];
	int i;
	//register hash
	if (register_hash(&sha256_desc) == -1) {
		serror("Error registering sha256");
		return FALSE;
	}
	*key_len = get_key_size(algo);
	//reset digest and key
	memset(digest, 0, 32);
	memset(key, 0, *key_len);
	//copy iv to digest
	memcpy(digest, iv, iv_len);
	// Hash the IV and password 8192 times
	for (i = 0; i < 8192; i++) {
		sha256_init(&md);
		sha256_process(&md, digest, 32);
		sha256_process(&md, (unsigned char*) passphrase, strlen(passphrase));
		sha256_done(&md, digest);
	}
	//though the digest is of 256 bits but we take only what we need
	memcpy(key, digest, *key_len);
	return TRUE;
}

/*
 * @@get_iv_size()
 * Description :Sets the size of iv for a crypto algorithm in
 * 				ucrypt_args.iv_len.
 */
unsigned int get_iv_size(crypt_algo_t algo) {
	unsigned int iv_len = 16;
	switch (algo) {
	case BLOWFISH:
		iv_len = 8;
		break;
	case CAST:
		iv_len = 8;
		break;
	case AES:
	default:
		//default is AES only
		iv_len = 16;
		break;
	}
	return iv_len;
}
unsigned int get_key_size(crypt_algo_t algo) {
	unsigned int key_len = 32;
	switch (algo) {
	case BLOWFISH:
		key_len = 32;
		break;
	case CAST:
		key_len = 16;
		break;
	case AES:
	default:
		//default is AES only
		key_len = 32;
		break;
	}
	return key_len;
}

/*
 * @@get_password()
 * Description: Reads password from a console if not provided at commandline.
 * 				saves the password read in
 * 				ucrypt_state.global_settings.passphrase
 */
UCRYPT_ERR get_password(char *passphrase, _uint16 *pass_len) {
	if(read_password(passphrase,pass_len)!= UCRYPT_OK){
		return UCRYPT_ERR_PASSWD_READ;
	}
	return UCRYPT_OK;
}
