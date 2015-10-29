/**
 * @file create_user.cpp
 * @brief Implementation of create_user module
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
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

extern "C" {
	#include "libscrypt.h"
	#include "b64.h"
}

//RSA private key generated by:
//openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:4096
unsigned char privateKey[]="-----BEGIN PRIVATE KEY-----\n"\
"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\n"\
"ccfBHl9s1IMYnur1znmfoqCyuoaHgf+y\n"\
"-----END PRIVATE KEY-----\n";

#define MAX_USERNAME 50

//parameters for Scrypt key derivation function 
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

//Encodes a binary safe base 64 string
int Base64Encode(const unsigned char* buffer, size_t length, char** b64text) { 
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	*b64text = (char*) malloc((bufferPtr->length + 1) * sizeof(char));
	memcpy(*b64text, bufferPtr->data, bufferPtr->length);
	(*b64text)[bufferPtr->length] = '\0';

	return 0; //success
}


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

int __encrypt(unsigned char *plaintext, int plaintext_len, 
		unsigned char *key, unsigned char *iv, unsigned char *ciphertext, 
		unsigned char *tag);

int __decrypt(unsigned char *ciphertext, int ciphertext_len,
		unsigned char *key, unsigned char *iv, unsigned char *tag,
		unsigned char *plaintext);

int encrypt(string plaintext, unsigned char *encrypted, int *len) {
	unsigned char plaintext_cstr[4096];
	strcpy((char *)plaintext_cstr, plaintext.c_str());
	int ret;
	unsigned char key[32], iv[16];	//256 bit key
	unsigned char ciphertext[10000];
	unsigned char plaintext2[10000];
	unsigned char tag[16];

	if (!RAND_bytes(key, sizeof key)) handleErrors();
	if (!RAND_bytes(iv, sizeof iv)) handleErrors();

	//aes-256-gcm encryped the username and password
	ret = __encrypt(plaintext_cstr, strlen((const char*)plaintext_cstr), key, iv, 
						ciphertext, tag);
	
	unsigned char key_vi_tag[32+16+16];
	memcpy(key_vi_tag, key, 32);
	memcpy(key_vi_tag+32, iv, 16);
	memcpy(key_vi_tag+32+16, tag, 16);

	//rsa encrypt the key, iv and tag used in gcm
	int encrypted_length= private_encrypt(key_vi_tag,32+16+16,privateKey,encrypted);
	memcpy(encrypted+512, ciphertext, ret);
	*len = ret+512;
	if(encrypted_length == -1) {
		printLastError("Private Encrypt failed");
		exit(EXIT_FAILURE);
	}
	return 0;
}


int __encrypt(unsigned char *plaintext, int plaintext_len, 
		unsigned char *key, unsigned char *iv, unsigned char *ciphertext, 
		unsigned char *tag)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the encryption operation. */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		handleErrors();

	/* Set IV length if default 12 bytes (96 bits) is not appropriate */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
		handleErrors();

	/* Initialise key and IV */
	if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/* Finalise the encryption. Normally ciphertext bytes may be written at
	 * this stage, but this does not occur in GCM mode
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	/* Get the tag */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
		handleErrors();

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

void CreateUser::AddUser(const string username, const string password) {
	string MCF = create_mcf(password.c_str());
	userlist.insert( pair<string, string>(username, MCF) );
}

void CreateUser::Save(const string filename) {
	int len;
	unsigned char encrypted[65535];
	//open file
	FILE *f = fopen(filename.c_str(), "wb");
	if (!f) {
		perror("Error in open the file");
		exit(EXIT_FAILURE);
	}

	//encrypt user list
	stringstream buffer;
	for(auto it = userlist.cbegin(); it != userlist.cend(); it++)
		buffer << it->first << ":" << it->second << endl;
	encrypt(buffer.str(), encrypted, &len);

	char *base64encode;
	Base64Encode(encrypted, len, &base64encode);
	printf("%s\n", base64encode);
	//write to file
	fwrite(base64encode, sizeof(char), strlen(base64encode), f);
	fclose(f);
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
	cu.Save("list.txt");

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
