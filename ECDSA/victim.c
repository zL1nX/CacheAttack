#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <time.h>
#include "cache_utils.h"



#define lfence() __asm__ volatile("lfence;");

EC_KEY *key;

EC_KEY* get_ec_key_from_file(const char* filename)
{
	FILE *fp = fopen(filename, "rb");
	EVP_PKEY *pk = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	EC_KEY *key;
	if(!pk)
	{
		printf("EVP PKEY Read Error.\n");
		return NULL;
	}

	key = EVP_PKEY_get1_EC_KEY(pk);
	if(!key)
	{
		printf("EVP PKEY Dump Error.\n");
		return NULL;
	}

	EVP_PKEY_free(pk);
	return key;
}


unsigned long do_timed_ecdsa_sign(EC_KEY *key)
{
    if(!key)
	{
		return 0;
	}
    printf("[*]Printing ECDSA Key.... \n\n");
	EC_KEY_print_fp(stdout, key, 0);
    printf("\n");

	int ret,size,i;
    unsigned int sig_len = 0;
	unsigned char *signature,digest[32]; 

	/* 获取密钥大小 */ 
	size=ECDSA_size(key); 

	for(i=0;i<32;i++){
		memset(&digest[i],i+1,1);
	}

	signature=malloc(size);
    ret = _ECDSA_sign(0,digest,32, signature, &sig_len, key);

    if(ret!=1) 
    {
        printf("[*]Sign error!\n"); 
        return -1;
    }
    printf("[*]ECDSA Sign Complete.\n");
	free(signature); 
    return 0;
}


int main()
{
	key = get_ec_key_from_file("ec_key.txt");
	int ret = do_timed_ecdsa_sign(key);
	EC_KEY_free(key);
	return 0;
}
