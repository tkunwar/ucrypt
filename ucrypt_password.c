/*
 * ucrypt_password.c
 */
#include "ucrypt_common.h"

/*
 * @@read_password()
 * Description: reads password from console and stores the read password to
 * 				buffer. Also returns the no. of chars read.
 */
unsigned short int read_password(char* buffer,unsigned short int *pass_len) {
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
		ucrypt_log_error(UCRYPT_ERR_TTY);
		return UCRYPT_ERR_TTY;
	}
	tty = fileno(ftty);
	if (tty < 0) {
		ucrypt_log_error(UCRYPT_ERR_TTY);
		return UCRYPT_ERR_TTY;
	}

	// Get the tty attrs
	if (tcgetattr(tty, &t) < 0) {
		fclose(ftty);
		ucrypt_log_error(UCRYPT_ERR_TTY);
		return UCRYPT_ERR_TTY;
	}

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
			ucrypt_log_error(UCRYPT_ERR_TTY);
			return UCRYPT_ERR_TTY;
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
			ucrypt_log_error(UCRYPT_ERR_PASSWD_READ);;
			return UCRYPT_ERR_PASSWD_READ;
		}
	}

	// check for EOF error
	if (c == EOF) {
		// For security reasons, erase the password
		memset(buffer, 0, MAX_PASSPHRASE_LEN + 1);
		fclose(ftty);
		ucrypt_log_error(UCRYPT_ERR_PASSWD_READ);;
		return UCRYPT_ERR_PASSWD_READ;
	}

	// Check chars_read.  The password must be maximum MAX_PASSPHRASE_LEN
	// chars.  If too long an error is returned
	if (chars_read > MAX_PASSPHRASE_LEN) {
		// For security reasons, erase the password
		memset(buffer, 0, MAX_PASSPHRASE_LEN + 1);
		fclose(ftty);
		ucrypt_log_error(UCRYPT_ERR_PASSWD_READ);;
		return UCRYPT_ERR_PASSWD_READ;
	}

	// Close the tty
	fclose(ftty);
	*pass_len=chars_read;
	return UCRYPT_OK;
}
