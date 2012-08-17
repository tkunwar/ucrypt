/*
 * ucrypt_password.c and ucrypt_password.h -- taken from AEScrypt
 *
 * AES Crypt for Linux
 * Copyright (C) 2007, 2008, 2009
 *
 * Contributors:
 *     Glenn Washburn <crass@berlios.de>
 *     Paul E. Jones <paulej@packetizer.com>
 *     Mauro Gilardi <galvao.m@gmail.com>
 *
 * This software is licensed as "freeware."  Permission to distribute
 * this software in source and binary forms is hereby granted without a
 * fee.  THIS SOFTWARE IS PROVIDED 'AS IS' AND WITHOUT ANY EXPRESSED OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 * THE AUTHOR SHALL NOT BE HELD LIABLE FOR ANY DAMAGES RESULTING FROM
 * THE USE OF THIS SOFTWARE, EITHER DIRECTLY OR INDIRECTLY, INCLUDING,
 * BUT NOT LIMITED TO, LOSS OF DATA OR DATA BEING RENDERED INACCURATE.
 *
 */

#include "ucrypt_common.h"

/*
 *  read_password_error
 *
 *  Returns the description of the error when reading the password.
 */
const char* read_password_error(int error) {
	if (error == AESCRYPT_READPWD_FOPEN)
		return "fopen()";
	if (error == AESCRYPT_READPWD_FILENO)
		return "fileno()";
	if (error == AESCRYPT_READPWD_TCGETATTR)
		return "tcgetattr()";
	if (error == AESCRYPT_READPWD_TCSETATTR)
		return "tcsetattr()";
	if (error == AESCRYPT_READPWD_FGETC)
		return "fgetc()";
	if (error == AESCRYPT_READPWD_TOOLONG)
		return "password too long";
	if (error == AESCRYPT_READPWD_NOMATCH)
		return "passwords don't match";
	return "No valid error code specified!!!";
}

/*
 *  read_password
 *
 *  This function reads at most 'MAX_PASSPHRASE_LEN'-1 characters
 *  from the TTY with echo disabled, putting them in 'buffer'.
 *  'buffer' MUST BE ALREADY ALLOCATED!!!
 *  When mode is ENC the function requests password confirmation.
 *
 *  Return value:
 *    >= 0 the password length (0 if empty password is in input)
 *    < 0 error (return value indicating the specific error)
 */

int read_password(char* buffer) {
	struct termios t; // Used to set ECHO attribute
	int echo_enabled; // Was echo enabled?
	int tty; // File descriptor for tty
	FILE* ftty; // File for tty
	int c; // Character read from input
	int chars_read; // Chars read from input
	char* p; // Password buffer pointer

	// Open the tty
	ftty = fopen("/dev/tty", "r+");
	if (ftty == NULL) {
		return AESCRYPT_READPWD_FOPEN;
	}
	tty = fileno(ftty);
	if (tty < 0) {
		return AESCRYPT_READPWD_FILENO;
	}

	// Get the tty attrs
	if (tcgetattr(tty, &t) < 0) {
		fclose(ftty);
		return AESCRYPT_READPWD_TCGETATTR;
	}

	// Round 1 - Read the password into buffer
	// Choose the buffer where to put the password
	p = buffer;

	fprintf(ftty, "Enter password: ");
	fflush(ftty);

	// Disable echo if necessary
	if (t.c_lflag & ECHO) {
		t.c_lflag &= ~ECHO;
		if (tcsetattr(tty, TCSANOW, &t) < 0) {
			// For security reasons, erase the password
			memset(buffer, 0, MAX_PASSPHRASE_LEN + 1);
			fclose(ftty);
			return AESCRYPT_READPWD_TCSETATTR;
		}
		echo_enabled = 1;
	} else {
		echo_enabled = 0;
	}

	// Read from input and fill buffer till MAX_PASSPHRASE_LEN chars are read
	chars_read = 0;
	while (((c = fgetc(ftty)) != '\n') && (c != EOF)) {
		// fill buffer till MAX_PASSPHRASE_LEN
		if (chars_read <= MAX_PASSPHRASE_LEN)
			p[chars_read] = (char) c;
		chars_read++;
	}

	if (chars_read <= MAX_PASSPHRASE_LEN + 1)
		p[chars_read] = '\0';

	fprintf(ftty, "\n");

	// Enable echo if disabled above
	if (echo_enabled) {
		t.c_lflag |= ECHO;
		if (tcsetattr(tty, TCSANOW, &t) < 0) {
			// For security reasons, erase the password
			memset(buffer, 0, MAX_PASSPHRASE_LEN + 1);
			fclose(ftty);
			return AESCRYPT_READPWD_TCSETATTR;
		}
	}

	// check for EOF error
	if (c == EOF) {
		// For security reasons, erase the password
		memset(buffer, 0, MAX_PASSPHRASE_LEN + 1);
		fclose(ftty);
		return AESCRYPT_READPWD_FGETC;
	}

	// Check chars_read.  The password must be maximum MAX_PASSPHRASE_LEN
	// chars.  If too long an error is returned
	if (chars_read > MAX_PASSPHRASE_LEN) {
		// For security reasons, erase the password
		memset(buffer, 0, MAX_PASSPHRASE_LEN + 1);
		fclose(ftty);
		return AESCRYPT_READPWD_TOOLONG;
	}

	// Close the tty
	fclose(ftty);
	return chars_read;
}

/*
 *  passwd_to_utf16
 *
 *  Convert String to UTF-16LE for windows compatibility
 */
int passwd_to_utf16(char *in_passwd, int length, int max_length,
		char *out_passwd) {
	char *ic_outbuf, *ic_inbuf;
	iconv_t condesc;
	size_t ic_inbytesleft, ic_outbytesleft;
	extern int errno;
	ic_inbuf = in_passwd;
	ic_inbytesleft = length;
	ic_outbytesleft = max_length;
	ic_outbuf = out_passwd;

	if ((condesc = iconv_open("UTF-16LE", nl_langinfo(CODESET)))
			== (iconv_t) (-1)) {
		perror("Error in iconv_open");
		return -1;
	}

	if (iconv(condesc, &ic_inbuf, &ic_inbytesleft, &ic_outbuf, &ic_outbytesleft)
			== -1) {
		switch (errno) {
		case E2BIG:
			fprintf(stderr, "Error: password too long\n");
			iconv_close(condesc);
			return -1;
			break;
		default:
			//~ printf("EILSEQ(%d), EINVAL(%d), %d\n", EILSEQ, EINVAL, errno);
			fprintf(stderr,
					"Error: Invalid or incomplete multibyte sequence\n");
			iconv_close(condesc);
			return -1;
		}
	}
	iconv_close(condesc);
	return (max_length - ic_outbytesleft);
}

