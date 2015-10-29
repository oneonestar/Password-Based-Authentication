all: authenticate_user create_user
authenticate_user: authenticate_user.cpp base64.c
	g++ authenticate_user.cpp base64.c libscrypt.a -O3 -o authenticate_user -std=gnu++11 -lcrypto

create_user: create_user.cpp base64.c
	g++ create_user.cpp base64.c libscrypt.a -O3 -o create_user -std=gnu++11 -lcrypto

debug: authenticate_user.cpp create_user.cpp
	g++ authenticate_user.cpp libscrypt.a -g -o authenticate_user -lcrypto
	g++ create_user.cpp libscrypt.a -g -o create_user -lcrypto

clean:
	rm -f create_user authenticate_user
