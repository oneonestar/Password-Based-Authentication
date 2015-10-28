all: authenticate_user create_user
authenticate_user: authenticate_user.cpp
	g++ authenticate_user.cpp libscrypt.a -O3 -o authenticate_user -std=gnu++11

create_user: create_user.cpp
	g++ authenticate_user.cpp libscrypt.a -O3 -o create_user

debug:
	g++ authenticate_user.cpp libscrypt.a -g -o authenticate_user
	g++ authenticate_user.cpp libscrypt.a -g -o create_user

clean:
	rm -f create_user authenticate_user
