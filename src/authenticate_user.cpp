/**
 * @file authenticate_user.cpp
 * @brief Implementation of authenticate_user module
 * @author Star Poon <star.poon@connect.polyu.hk>
 * @version 1.0
 * @copyright 2015
 *
 * @section LICENSE
 * Copyright (C) 2015 Star Poon
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <string>
#include <sstream>
#include <map>
#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

extern "C" {
	#include "libscrypt.h"
	#include "b64.h"
	#include "base64.h"
}

//use public key to decrypt the data in list.txt
//Generated by:
//openssl rsa -in key.pem -pubout
unsigned char publicKey[]="-----BEGIN PUBLIC KEY-----\n"\
"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApLy+6mhH5DDO500UgyNQ\n"\
"+vlUB2q81PM9hzdZWi8zWC00PiI01/D4A6wvsZhkDi7O6twvfKJw8uuKv31G6Jq5\n"\
"Mb16SwK/ZTMkhZo7K4kLInm6KBffghV0YiO13YjvApd5WcfrV01bM0iulAaKjbk2\n"\
"X2QqU3SYndCFzymMvYKX8DweQRDIYn9c80rnCOVE7NcF6KfQDwZvpSYYafAuKCHo\n"\
"HPoZfkm9fCBlzmNSXTfyf6J4KyBl5mfvb6StRq5z+nl0hISgDrOCmbN9HJO6F9D5\n"\
"5QYrIb76xIhhdFiq+64maQwFEQHQb9BbrhmipyAGiw80Qu+RfpB7H+pMqAiIonWP\n"\
"4GYSPXLWxUXzp6jCWGVol6wfikj1xXA3xWG6kzbORi5PPW5Fm+SUeaHfGIvaOEGv\n"\
"sGT2qPHMC+oYjzvJHUDBEt5s/aUqYjIblqGKs5CO/TUURgGjUIvPGFS8+IZYKhqR\n"\
"p5GgY0KQUisqXSJBXIgPjUeSPArfbZD9I6WdLDejDsHsM2QBoFkCkYP7Pc1YkQ5Y\n"\
"LLvwmENYSZpeRUHdOD52dGvbnuzY2R2KclD2IFDRjBnvWtzVMbv7k6Pdgr5dKJ+l\n"\
"X7kyy1u1BK+hnqAoZOyfPUrR1w3y9pHfCLXsiZuUn6Xsn7SHz1yLe4Vq4E+r7E8S\n"\
"xzKBHUz3LWEMp6j5xlC7o8cCAwEAAQ==\n"\
"-----END PUBLIC KEY-----\n";


#define MAX_USERNAME 50

using namespace std;

class AuthenticateUser {
	public:
		bool VerifyUser(const string username, const string password);
		void Load(const string filename);
		void Print();
	private:
		std::map<string, string> userlist;
};

int padding = RSA_PKCS1_PADDING;

RSA * createRSA(unsigned char * key,int isPublic)
{
	RSA *rsa= NULL;
	BIO *keybio ;
	keybio = BIO_new_mem_buf(key, -1);
	if (keybio==NULL) {
		printf( "Failed to create key BIO");
		return 0;
	}
	if(isPublic) {
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
	} else {
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
	}
	if(rsa == NULL)	{
		printf( "Failed to create RSA");
	}

	return rsa;
}

int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
	RSA * rsa = createRSA(key,0);
	int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
	return result;
}
int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
	RSA * rsa = createRSA(key,1);
	int result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
	return result;
}

void printLastError(const char *msg)
{
	char * err = new char[130];
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), err);
	printf("%s ERROR: %s\n",msg, err);
	delete(err);
}


void handleErrors(void) {
	ERR_print_errors_fp(stderr);
	abort();
}

int __decrypt(unsigned char *ciphertext, int ciphertext_len,
		unsigned char *key, unsigned char *iv, unsigned char *tag,
		unsigned char *plaintext);

bool AuthenticateUser::VerifyUser(const string username, const string password) {
	// verify the password
	// copy mcf because libscrypt_check will modify the mcf
	char mcf [SCRYPT_MCF_LEN];
	map<string,string>::iterator it;
	it = userlist.find(username);

	if (it == userlist.end()) return false;
	memcpy(mcf, it->second.c_str(), SCRYPT_MCF_LEN);	//skip username
	int ret = libscrypt_check(mcf, password.c_str());
	if(ret<0) {
		printf("Error in checking the password!\n");
		exit(EXIT_FAILURE);
	} else if (ret==0) {
		//printf("Password is incorrect!\n");
		return false;
	} else {
		return true;
		//printf("Password is correct!\n");
	}
}

void AuthenticateUser::Load(const string filename) {
	unsigned char ciphertext[65535];
	//open file
	FILE *f = fopen(filename.c_str(), "rb");
	if (!f) {
		perror("Error in open the file");
		exit(EXIT_FAILURE);
	}

	char b64file[65536]={};
	unsigned char plaintext[65536]={};
	int ret;
	unsigned char rsa_key_iv_tag[512];
	unsigned char key_iv_tag[512];
	//unsigned char key[32], iv[16];	//256 bit key
	//unsigned char tag[16];

	//fgets(b64file, sizeof(b64file), f);
	ret = fread(b64file, sizeof(char), sizeof(b64file), f);
	b64file[ret] = '\0';
	if (ret<=512) {
		cerr << "Failed to decrypt file!" << endl;
		exit(EXIT_FAILURE);
	}
	size_t length = Base64decode_len(b64file)-2;
	char *base64DecodeOutput = new char[length+2];
	Base64decode(base64DecodeOutput, b64file);
	memcpy(rsa_key_iv_tag, base64DecodeOutput, 512);
	memcpy(ciphertext, base64DecodeOutput+512, length-512);
	ret = length-512;

	int decrypted_length = public_decrypt(rsa_key_iv_tag, 512, publicKey, key_iv_tag);
	if(decrypted_length == -1) {
		printLastError("Public Decrypt failed");
		exit(0);
	}

	ret = __decrypt(ciphertext, ret, key_iv_tag, key_iv_tag+32, key_iv_tag+32+16, plaintext);
	if(ret==-1) {
		perror("Failed to decrypt file!\n");
		exit(EXIT_FAILURE);
	}

	char *p = strtok((char*)plaintext, "\n");
	while (p) {
		if(strlen(p)<=1) break;
		char username[50];
		char password[150];
		char* pos = strchr(p, ':');
		strncpy(username, p, pos-p);
		strncpy(password, pos+1, 150);

		userlist.insert( pair<string,string>(username, password) );
		p = strtok(NULL, "\n");
	}

	fclose(f);
}

void AuthenticateUser::Print() {
	for(auto it = userlist.cbegin(); it != userlist.cend(); it++)
		cout << it->first << ":" << it->second << endl;
}

int __decrypt(unsigned char *ciphertext, int ciphertext_len,
		unsigned char *key, unsigned char *iv, unsigned char *tag, 
		unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	int ret;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the decryption operation. */
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		handleErrors();

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
		handleErrors();

	/* Initialise key and IV */
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
		handleErrors();

	/* Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plaintext is not trustworthy.
	 */
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0)
	{
		/* Success */
		plaintext_len += len;
		return plaintext_len;
	}
	else
	{
		/* Verify failed */
		return -1;
	}
}



int main()
{
	AuthenticateUser cu;
	cu.Load("list.txt");
	cu.Print();
	cout << cu.VerifyUser("STAR", "A") << endl;
	cout << cu.VerifyUser("STAR", "pw") << endl;
	cout << cu.VerifyUser("STAR2", "PW") << endl;
	cout << cu.VerifyUser("STAR", "PW") << endl;

	return 0;
}