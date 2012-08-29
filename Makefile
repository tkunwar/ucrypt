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
	./ucrypt --encrypt --crypt_algo=blowfish --pass=system@123 test.pdf
analyze:
	./ucrypt --analyze test.pdf.uff
decrypt:
	./ucrypt --decrypt --pass=system@123 test.pdf.uff
	
clean:
	rm -f *.o *.out ucrypt
