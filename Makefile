#
# Makefile for xmp_crypt
CC=gcc

#The below line is for debugging
#CFLAGS=-I. -ggdb -Wall -D_FILE_OFFSET_BITS=64
CFLAGS=-Wall -g  -D_FILE_OFFSET_BITS=64 -lm

LIBS=

#Uncomment the line below to compile on Mac
#LIBS=-liconv
all:ucrypt
ucrypt: ucrypt_crypt.o ucrypt_error.o ucrypt_common.o ucrypt_crypt_handler.o ucrypt_password.o libtomcrypt.a
	$(CC) $(LIBS) -o $@ $^ $(CFLAGS)


%.o: %.c %.h
	$(CC) -c $*.c $(CFLAGS)

install: ucrypt
	mkdir -p /opt/ucrypt
	install -o root -g root -m 755 ucrypt /opt/ucrypt

uninstall:
	rm -f /opt/ucrypt
encrypt:
	./ucrypt --encrypt --src_file=test.pdf --out_file=test.pdf.enc --crypt_algo=blowfish --pass=system@123
analyze:
	./ucrypt --analyze --src_file=test.pdf.enc
decrypt:
	./ucrypt --decrypt --src_file=test.pdf.enc --out_file=test_decrypted.pdf --pass=system@123
	
clean:
	rm -f *.o *.out ucrypt
