/*
 * ucrypt_crypt.h
 */
#ifndef __UCRYPT_H__
#define __UCRYPT_H__

#include "ucrypt_common.h"
#include "ucrypt_version.h"

/* a job queue  can be in two modes -- batch mode and global mode. In global
 * mode, we need only the file_path while in batch_mode, all usual parametres
 * are needed as these can be provided per file.
 *
 * In global_mode, fields of JOB_DESC other than file_path are ignored.
 */
struct job_desc_t{
	    char passphrase[MAX_PASSPHRASE_LEN];
	    _uint16 pass_len;
		char file_path[FILE_PATH_LEN];
		ucrypt_actions_t action;
		crypt_algo_t crypt_algo;
};

//create a queue of all the files to process
struct job_queue{
	struct job_desc_t job;
	struct job_queue *next;
};

//store info about global task
struct global_settings_t{
	char passphrase[MAX_PASSPHRASE_LEN];
	_uint16 pass_len;
	ucrypt_actions_t action;
	crypt_algo_t crypt_algo;
};

//program global state
struct UCRYPT_STATE{
	struct job_queue *job_q; //list of files queued
	struct job_queue *last_queued_node;
	struct global_settings_t global_settings;
	UCRYPT_BOOL batch_mode; //by default will be false--use global settings
							//only when batch_file="" option is provided
							//it will be set to true
	_uint16 job_length;
	int skipped_jobs;
};

/*function prototypes*/
UCRYPT_ERR generate_header(FILE *outfp,crypt_algo_t algo,_uchar *iv,
		_uint16 iv_len);
UCRYPT_ERR encrypt_main(FILE *infp, FILE *outfp,struct job_desc_t *job);
UCRYPT_ERR decrypt_main(FILE *infp, FILE *outfp,struct job_desc_t *job);
UCRYPT_ERR process_args(int argc, char *argv[]);
UCRYPT_ERR check_if_ucrypt_args_populated();
void print_usage();
void print_version();
void cleanup(const char *src_file);
UCRYPT_BOOL create_iv(crypt_algo_t algo,_uchar *iv,_uint16 *iv_len);
UCRYPT_BOOL create_key(crypt_algo_t algo,_uchar *key,_uint16 *key_len,
		_uchar *iv,_uint16 iv_len,char *passphrase);
unsigned int get_iv_size(crypt_algo_t algo);
unsigned int get_key_size(crypt_algo_t algo);
UCRYPT_ERR get_password(char *pass,_uint16 *passlen);
UCRYPT_ERR set_crypt_algo(char *optarg);
void init_ucrypt_state();
UCRYPT_ERR load_job_from_file(char *batch_file_path);
UCRYPT_ERR enqueue_job(struct job_desc_t *job);
struct job_desc_t dequeue_job(int *job_state);
UCRYPT_ERR job_manager();
void check_job_state(struct job_desc_t *job);
void skip_job(UCRYPT_ERR err_code);
void print_job_queue();

#endif
