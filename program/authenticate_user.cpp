#include <string>
#include <map>
#include <iostream>
#include <cstdio>
#include <cstring>
#include <cstdlib>
extern "C" {
	#include "libscrypt.h"
	#include "b64.h"
}

#define MAX_USERNAME 50
#define N 1<<20
#define R 8
#define P 1

using namespace std;

class CreateUser {
	public:
		void AddUser(const string username, const string password);
		void Save(const string filename);
		void Print();
	private:
		std::map<string, string> userlist;
		static string create_mcf(char const *password);
};

void CreateUser::AddUser(const string username, const string password) {
	string MCF = create_mcf(password.c_str());
	userlist.insert( pair<string, string>(username, MCF) );
}

void CreateUser::Print() {
	for(auto it = userlist.cbegin(); it != userlist.cend(); it++)
		cout << it->first << ":" << it->second << endl;
}

string CreateUser::create_mcf(char const *password) {
	uint8_t hashbuf[SCRYPT_HASH_LEN];
	char hashbuf2[SCRYPT_HASH_LEN*2];
	uint8_t saltbuf[SCRYPT_SALT_LEN];
	char saltbuf2[SCRYPT_SALT_LEN*2];
	char mcf[SCRYPT_MCF_LEN];
	int ret;

	// Generate salt
	ret = libscrypt_salt_gen((uint8_t*)saltbuf, SCRYPT_SALT_LEN);
	if(ret != 0) {
		printf("Failed to generate salt!\n");
		exit(EXIT_FAILURE);
	}

	// run scrypt hash
	ret = libscrypt_scrypt((uint8_t*)password, strlen(password), saltbuf, sizeof(saltbuf), N, R, P, hashbuf, sizeof(hashbuf));
	if(ret != 0) {
		printf("Failed to create hash!\n");
		exit(EXIT_FAILURE);
	}

	// convert salt and hash result to base64
	ret = libscrypt_b64_encode(saltbuf, sizeof(saltbuf), saltbuf2, sizeof(saltbuf2));
	if(ret <= 0) {
		printf("Failed to convert to base64!\n");
		exit(EXIT_FAILURE);
	}
	ret = libscrypt_b64_encode(hashbuf, sizeof(hashbuf), hashbuf2, sizeof(hashbuf2));
	if(ret <= 0) {
		printf("Failed to convert to base64!\n");
		exit(EXIT_FAILURE);
	}

	// create MCF presentation
	ret = libscrypt_mcf(N, R, P, saltbuf2, hashbuf2, mcf);
	if(ret != 1) {
		printf("Failed to convert to base64!\n");
		exit(EXIT_FAILURE);
	}

	// join username and password hash
	return string(mcf);
}

int main()
{
	// create a mcf
	CreateUser cu;
	cu.AddUser("STAR","PW");
	cu.AddUser("STAR2","PW123");
	cu.Print();
	/*
	// verify the password
	// copy mcf because libscrypt_check will modify the mcf
	memcpy(mcf2, mcf, SCRYPT_MCF_LEN);	//skip username
	ret = libscrypt_check(mcf2, "pw1");
	if(ret<0) {
		printf("Error in checking the password!\n");
		exit(EXIT_FAILURE);
	} else if (ret==0) {
		printf("Password is incorrect!\n");
	} else {
		printf("Password is correct!\n");
	}

	// verify the password
	// copy mcf because libscrypt_check will modify the mcf
	memcpy(mcf2, mcf, SCRYPT_MCF_LEN);
	ret = libscrypt_check(mcf2, "password");
	if(ret<0) {
		printf("Error in checking the password!\n");
		exit(EXIT_FAILURE);
	} else if (ret==0) {
		printf("Password is incorrect!\n");
	} else {
		printf("Password is correct!\n");
	}
*/
	return 0;
}
