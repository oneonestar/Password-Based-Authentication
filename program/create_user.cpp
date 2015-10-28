#include <stdio.h>
#include <string.h>
#include "libscrypt.h"

#define N 1<<20
#define R 8
#define P 1


int main()
{
	uint8_t hashbuf[SCRYPT_HASH_LEN];
	char mcf[SCRYPT_MCF_LEN];
	char saltbuf[64];
	int ret;
	
	ret = libscrypt_scrypt((uint8_t*)"password", strlen("password"), (uint8_t*)"salt", strlen("salt"), N, R, P, hashbuf, sizeof(hashbuf));
	ret = libscrypt_mcf(N, R, P, "salt", hashbuf, mcf);
	printf("%s\n", mcf);
	return 0;
}
