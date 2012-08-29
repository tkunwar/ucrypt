This document outlines general design, and coding approach followed. It may 
also include features already built or expected. As such it provides general
theory behind ucrypt development.


1. algorithm supported  :
	<algoirthms> :
	AES : AES algorithm (using 256 bit key size)
	CAST : CAST5 or CAST128 (using 128 bits key size)
	BLOWFISH : blowfish algorithm (using 256 bit key size)
	
2. block size is fixed for algos :
	CAST-64,
	AES-128,
	BLOWFISH-64

3. File format :
	File format is composed of a series of frames. Each frame is represented 
	as a collection of {<attribute_code><attribute_length><attribute_data>}
	
	<attribute_code> and <attibute_length> both are short integers and require 
	2 bytes. However if attribute code is 1 (meaning this attribute will store
	payload), then attribute length is extended to 8 bytes (sizeof(unsigned 
	long long int)).
	
	attibute codes being used as of now(with <attribute_data> type mentioned 
	against them) :
	0=end_markers ,  1=payload_marker (<binary>),
	2=program_header (<char string>),3=file_format_version (<char string>),
	4=iv (<binary>),			5,=hmac (<binary>)
	6=PROG_NAME (<char string>)		7=PRG_VERSION_STRING (<char string>)
	8=crypt_algo (<char string>, int stored as string)
	9= hashed password (<binary>)
	
4. Features to be implemented :
	1.  batch processing --load job information from files. provide a basic 
		scripting interface
	2.	automatically add ".uef" extension to all files when encrypting files
		thus in most cases output file name may not needed.
		
5.	Error handling:
	1. All routines must return UCRYPT_OK or an error_code as defined in 
	ucrypt_error.h  except those whose return type is void.

6.	Batch processing :
	Ucyrpt can encrypt or dercrypt multiple files at a time without user 
	intervention in two ways :
	1. Accept arguments from commandline
	2. Load actions from a job file
	
	Both these modes are exclusive to each other - at a time one it will run in 
	only one of these modes.
	**Note** : When in batch mode we  will ignore some/more parameters
	
	1. Accept arguments from commandline:
		1. Action can be only one
		2. accept mulitple file names but only one action (encrypt,decrypt or 
		   analyze ) will apply to all of them.
		3. All these files will be treated as source_files -- no output file 
		   must be specified when dealing with multiple files.
		4. Therfore, files need not be specified wirth --out_file or --src_file
		   options. They can just be provided after the required parametres.
		5. Only one password and algorithm will apply to all files. No different
		   password or algorithm for individual files. If different configuration 
		   is to be used then use ucrypt in single file mode.
		6. For e.g
			ucrypt --encrypt --crypt_algo=aes --pass=system@123 file1 file2 
			file3 file4
			
			ucrypt --decrypt --pass=system@123 file1.uff file2.uff file3.uff
			
			ucrypt --analyze file1.uff file2.uff file3.uff
			
	2. Load job information from a job file
		1. Individual files may be provided different configuration.
		2. Therefore, for some files action may be to encrypt while for some it
			may be to decrypt.
		3. An extra option "--batch=batch_file_name" must be provided in order 
		   for ucrypt to load the job information.
		4. Structure of a batch file :
			Two sections :
			1. config section and 2. job description section
			
			1. About Config section:
				config section specifies the global options for the entire job
				file. 
			config={crypt_algo="aes";
					pass="system@123";
					global="true";
					};
			2. About job description section:
				Feilds needed <file_path>,<crypt_algo>,<passphrase>. Note that
				fields <crypt_algo> and <passphrase> are not needed if <global>
				fields is set to true in config section. 
				job_list={{"file1","aes","system@123"},
						   {"file2","blowfish","213#hsjd"}
				} ;
	
7.	General Information :
	File format : "uff" : "ucrypt file format"
	File format header TAG : "uff"     
	
	Note about extensions:
		1. Extension "uff" is appended to every ucrypt encrypted file. Therefore
		   this extension must be present in every file that needs to be 
		   decrypted.
		2. Files not ending with ".uff" will not be decrypted.
		
8.	Error reporting :
	We will be dealing with debugging messages,warning and error messages. Now 
	for debugging messages and warning messages, use sdebug()/var_debug() and 
	swarn()/var_warn() macros respectively however for error reporting make 
	use of ucrypt_log_error(error_code).
	 
	The error codes passed to ucrypt_log_error() will also be returned to the
	caller routine. Note that error will be reported only at the origin location
	and no error reporting in backward control propagation, only error code 
	will be returned to caller.
	
	routines retutn UCRYPT_OK or an error code of ucrypt_codes_t where an error 
	is expected, do not use TRUE or FALSE as return variables when you need to
	check for an error condition. TRUE and FALSE should be used for comparison,
	assignment as in flag values.