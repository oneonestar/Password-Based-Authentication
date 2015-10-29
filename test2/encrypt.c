#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <string.h>
#include <stdio.h>


int padding = RSA_PKCS1_PADDING;

RSA * createRSA(unsigned char * key,int public)
{
RSA *rsa= NULL;
BIO *keybio ;
keybio = BIO_new_mem_buf(key, -1);
if (keybio==NULL)
{
printf( "Failed to create key BIO");
return 0;
}
if(public)
{
rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
}
else
{
rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
}
if(rsa == NULL)
{
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

void printLastError(char *msg)
{
char * err = malloc(130);;
ERR_load_crypto_strings();
ERR_error_string(ERR_get_error(), err);
printf("%s ERROR: %s\n",msg, err);
free(err);
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

int encrypt(unsigned char *plaintext) {

char plainText[2048/8] = "Hello this is Ravi"; //key length : 2048

char publicKey[]="-----BEGIN PUBLIC KEY-----\n"\
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

char privateKey[]="-----BEGIN PRIVATE KEY-----\n"\
"MIIJRAIBADANBgkqhkiG9w0BAQEFAASCCS4wggkqAgEAAoICAQCkvL7qaEfkMM7n\n"\
"TRSDI1D6+VQHarzU8z2HN1laLzNYLTQ+IjTX8PgDrC+xmGQOLs7q3C98onDy64q/\n"\
"fUbomrkxvXpLAr9lMySFmjsriQsiebooF9+CFXRiI7XdiO8Cl3lZx+tXTVszSK6U\n"\
"BoqNuTZfZCpTdJid0IXPKYy9gpfwPB5BEMhif1zzSucI5UTs1wXop9APBm+lJhhp\n"\
"8C4oIegc+hl+Sb18IGXOY1JdN/J/ongrIGXmZ+9vpK1GrnP6eXSEhKAOs4KZs30c\n"\
"k7oX0PnlBishvvrEiGF0WKr7riZpDAURAdBv0FuuGaKnIAaLDzRC75F+kHsf6kyo\n"\
"CIiidY/gZhI9ctbFRfOnqMJYZWiXrB+KSPXFcDfFYbqTNs5GLk89bkWb5JR5od8Y\n"\
"i9o4Qa+wZPao8cwL6hiPO8kdQMES3mz9pSpiMhuWoYqzkI79NRRGAaNQi88YVLz4\n"\
"hlgqGpGnkaBjQpBSKypdIkFciA+NR5I8Ct9tkP0jpZ0sN6MOwewzZAGgWQKRg/s9\n"\
"zViRDlgsu/CYQ1hJml5FQd04PnZ0a9ue7NjZHYpyUPYgUNGMGe9a3NUxu/uTo92C\n"\
"vl0on6VfuTLLW7UEr6GeoChk7J89StHXDfL2kd8IteyJm5SfpeyftIfPXIt7hWrg\n"\
"T6vsTxLHMoEdTPctYQynqPnGULujxwIDAQABAoICAQCD/902dIKOfPF88w1pmsXL\n"\
"pDbJjqRqOdFmZFpLYiDRGb+Pvdb75NDGGJVKx6H8n1Mba3z9cCfy7fuKPnav8TJN\n"\
"gdbY/gWgsF8mUpPw6WmroUAh2ic0074i2Rxju9JQEFGjOAcCODDIogeJAsjIkMzZ\n"\
"mKg1oOqdIbXmbhOg0mCulW1kk28NRaKUK8N+JD+bSxwn9TdIos6Y1TKgyFwjui+D\n"\
"8H62651SNZ99xaX8ndTIosWJQPeFrGh1280gIq8511Ie0SpzPTF7uQ+Z82Ecrk1e\n"\
"TxgGfUHwcpssH9Q5wKx0ZbY1j2+V+K1Njqr/ITE9AdzNearqcBjIVPRBfD0HeA3k\n"\
"5qK80eFP04oew3/yYmKqIe05oO++mv5E2qvHskZMfRreffRoHVb6RUEyFYNapHxX\n"\
"/rhpllz5e00kf2IH05hLQjSycj8X4OClZZeewd/NFiDJpky4DZbOQcg3PqZ02b7A\n"\
"8Jq67xv5M4tyQnCLEatp+giqyLshx3C1PTXkQGU1H21G/ilMnbFSyuXbQbASFa7J\n"\
"OZ3icF5T8LxQ6NC5nhevwxPD2Kt3fx9fRI/ktUERKSx0vSz+67OnttxyU7DYvfz/\n"\
"p4A3fNNf+duFjFFy3jyyqA1t3pqdGOoYk8StspAZjAIcMbEpCmVxrUFLKl/9ioax\n"\
"Pp8Ho74W3aws7jo8aX3GQQKCAQEA0CFp51zGlXtdlIEJqzwCpJewlWRla9U7ruBL\n"\
"6gURMrY+LIM/aTYgII9Nb2A9ZDV+2LZw/7B0dD6khvNhjJUK/pM0fGPlyqgechVl\n"\
"MqDrTE5vqCtMSXPgsKJtO+AmTS1/NDfgHnnI95V6WPT8++ztSLHdpymS4tTlYaQd\n"\
"nE2BQ/SRrDFAwpFQ1qqA0c3U6EELnKFqp/vyGe7fNUaHfyEF+4wMXLVre7DuEcRv\n"\
"oLlN7gahSHBObwc2s49bELQPWkTq+Gx+icWlcCPHC+I+OTFM+bnr1NoBgWDKvCgp\n"\
"ICFaI+NIgL7NicpqWgqpfYZODVMAaQy0zBdaer0hoT+qI4jtJwKCAQEAyqBeDgIq\n"\
"EpHGOPDWNM8aEJitFvUL3I/RRgA8+/Vxl2y79WXh6pODYo2bRkIBLxRpSwCI/lEe\n"\
"pa05VRoujOxEReTjR5tit8xH1EqERaZasW/+q4hRHd9kvdOgqdlsoMq9FZE1/EKG\n"\
"ujN60+5/gbrMn7fvvXRP/TZh2nGHv6uKPgKtJxCE/lLej+CHrAeEIa3axPrtrNQz\n"\
"ll8PNeBsJIRzigJZKHIrDTyHzRCpLf9C7GeQCq6WYTURERp4MWL5j17b20LSY7eb\n"\
"rBvQX++sRagcyF/Fh42Y+7DNkuYZiREtM2UZ+TSl5xmYrknttR7bZDgQHqnIe7LK\n"\
"Z1nrQJuENIT4YQKCAQEAr/+BaZcHioJeuOSBQ56kcYCgX0Qdi5kuNgwPxd3xFBwN\n"\
"6WA3MAYIFuB3T7ZnU6T1Fdb5KQ6S+3W5dTC8DcA/ItViLcngGIYf8MLs52oybz1o\n"\
"qCGtCfQGTfecPWSnnt3ZUlPpnnvHmK17X1wTzgklAjL+R4wdXNlA+1dnfrP/mnJm\n"\
"+OBRbfaqEEzwT/opjxjp89J/uXuQ16MqdwekLrnDMFrWXVNAh8EvIDEnYBcyshRD\n"\
"MFlfyf2koSSZkj9hOClNNTOxsVlEM9bdS8xOZ9irygURStXrLfemmIOxey0Y534b\n"\
"4lr2vg0/79JSTwZSXGwSzcJj5K3e4imrFYsbmZ8BQwKCAQEAig68JtVIr0BNi8xk\n"\
"VrTpMHemL6ckvtHqp8RPyOhRzfeTFT+mrvp1IXgUXMlqHxbMKwMhVA4XUJD3KEnf\n"\
"f7sXRXwPc2Gm4E46fqWK/B29W3pQTbVid3UXIdOIe1GeFuwr6v72hnsZatLalH3C\n"\
"uLR66TQdD7upKICeKYUDFhAd7+RI7/3sb5As/mDgb9DrMTtQfLfvqrsmrwTzyySu\n"\
"6i6ovladQtaPCMS+TnVUn/d1NLfXR7/uzCqpBzs+u3+RRCNAr2MXEEQwuBJ3ZnZZ\n"\
"rVg+zDOc1aAfpRWw668FpQNkBcmT6dz6ULx67/2FDcwJdX5RVWMfK1EFYWe9x1Zu\n"\
"vI4A4QKCAQAtHospEbNcFj5WEq2N4Y7G1X9rHWarlAs8MdzL9JKGVkvvSH5RNMIW\n"\
"tSgZWTX2DgSJtwBuzn5B90sIz3U+BFtXSROdfY6QcBr9OPRVeyCBSiWYtotUMOpr\n"\
"cuNBbJkWtD+atrwtmJ33hJ+DWlQBFp9K+o3cpR1upiXNsDCvOmb82pAaE88bvaUt\n"\
"lzn8SjKQg+wP/tKZSgkVQwILZ/LBfcQTuV7gD1GCcCWTZ+d+7y/3mhGNWS0NBWun\n"\
"hQztD9qqbTaNwTv1z0g8x6IuIMSFkkekDe7ibTzvlGsGDZBMvQGEeLLQ7aIXpqzU\n"\
"ccfBHl9s1IMYnur1znmfoqCyuoaHgf+y\n"\
"-----END PRIVATE KEY-----\n";


	unsigned char encrypted[4098]={};
	int ret;
	unsigned char key[32], iv[16];	//256 bit key
	unsigned char ciphertext[10000];
	unsigned char plaintext2[10000];
	unsigned char tag[16];

	if (!RAND_bytes(key, sizeof key)) handleErrors();
	if (!RAND_bytes(iv, sizeof iv)) handleErrors();

	ret = __encrypt(plaintext, strlen(plaintext), key, iv, 
						ciphertext, tag);
	
	char arr[32+16+16];
	memcpy(arr, key, 32);
	memcpy(arr+32, iv, 16);
	memcpy(arr+32+16, tag, 16);

int encrypted_length= private_encrypt(arr,32+16+16,privateKey,encrypted);
if(encrypted_length == -1)
{
printLastError("Private Encrypt failed");
exit(0);
}

int decrypted_length = public_decrypt(encrypted,encrypted_length,publicKey, decrypted);
if(decrypted_length == -1)
{
printLastError("Public Decrypt failed");
exit(0);
}




	//ret = __decrypt(ciphertext, ret, tag, key, iv, plaintext2);
	ret = __decrypt(ciphertext, ret, decrypted, decrypted+32, decrypted+32+16, plaintext2);
	if(ret==-1) {
		perror("Failed to decrypt file!\n");
		exit(EXIT_FAILURE);
	}
	printf("%s\n", plaintext2);
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
		printf("%d\n", plaintext_len);
		return plaintext_len;
	}
	else
	{
		/* Verify failed */
		return -1;
	}
}


int main() {
	encrypt("ABCDE");
	encrypt("ABDCDE");
	encrypt("ABDCDEF");
	encrypt("ABDCDEFG");
	encrypt("ABDCDEFGH");
	return 0;
}
