CC=g++
CFLAGS= -c -Wall -Wnarrowing 

all: keepPass

keepPass: KeepPass.o cpputility.o aes.o SHA1.o HMAC.o pbkdf2.o
	$(CC) KeepPass.o cpputility.o aes.o SHA1.o HMAC.o pbkdf2.o -o keepPass

KeepPass.o: KeepPass.cpp PassClass.h
	$(CC) $(CFLAGS) KeepPass.cpp

cpputility.o: Utility/cpputility.cpp
	$(CC) $(CFLAGS) Utility/cpputility.cpp

aes.o: AES/aes.cpp
	$(CC) $(CFLAGS) AES/aes.cpp

SHA1.o: PBKDF/SHA1.cpp  
	$(CC) $(CFLAGS) PBKDF/SHA1.cpp
	
HMAC.o: PBKDF/HMAC.cpp 
	$(CC) $(CFLAGS) PBKDF/HMAC.cpp
	
pbkdf2.o: PBKDF/pbkdf2.cpp
	$(CC) $(CFLAGS) PBKDF/pbkdf2.cpp
	

clean:
	rm *.o key.asc
