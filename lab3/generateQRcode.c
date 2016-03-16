#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

#define TARGET_HEX_SIZE 20	//20 HEX -> 80 bits bruh bruh
#define TARGET_BIT_SIZE 10

#define TOTP_DEFAULT_LEN 40
#define HOTP_DEFAULT_LEN 41
void print_output(const char *issuer, const char *accountName, const char *secret_hex){
	//First create the HOTP string
	if(!issuer || !accountName || !secret_hex){
		printf("One of the parameters is null. The QR code could not be generated.\n");
		return;
	}
	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
	issuer, accountName, secret_hex);

	const char *encoded_issuer = urlEncode(issuer);	//encode the issuer

	const char *encoded_account_name = urlEncode(accountName);	//encode the account name

	int secret_hex_len = strlen(secret_hex);		//Let's get the length of the hex first.

	char secret[TARGET_HEX_SIZE + 1]; 	//Target hex size of 20 plus null char

	//If the length of the secret_hex is less than the target hex size of 20. Append Zeros
	if(secret_hex_len < TARGET_HEX_SIZE){
		int diff = TARGET_HEX_SIZE - secret_hex_len;	//Get number of leading zeros needed.

		int i;
		for(i = 0; i < diff; i++){
			secret[i] = '0';
		}

		for (; i < TARGET_HEX_SIZE; i++){
			secret[i] = secret_hex[i - diff];
		}

		secret[i] = '\0';
	}

	else{
		//If length is fine, just copy the input into secret
		strncpy(secret, secret_hex, TARGET_HEX_SIZE);
	}

	char b32_encoded_secret[TARGET_BIT_SIZE + 1];	//Create a buffer for storing the base 32 encoded string.

	//Encode the secret hex into base32
	base32_encode((const uint8_t *)secret, strlen(secret), (uint8_t *)b32_encoded_secret,
                  TARGET_BIT_SIZE);	

	int hotp_uri_len = HOTP_DEFAULT_LEN + strlen(encoded_issuer) + strlen(encoded_account_name) + strlen(b32_encoded_secret);
	int totp_uri_len = TOTP_DEFAULT_LEN + strlen(encoded_issuer) + strlen(encoded_account_name) + strlen(b32_encoded_secret);

	char *hotp_uri = (char*) malloc(hotp_uri_len*sizeof(char));
	char *totp_uri = (char*) malloc(totp_uri_len*sizeof(char));

	//Create and format the HOTP URI
	sprintf(hotp_uri, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", encoded_account_name, encoded_issuer, b32_encoded_secret);
	//Create and format the TOTP uri
	sprintf(totp_uri, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encoded_account_name, encoded_issuer, b32_encoded_secret);

	displayQRcode(hotp_uri);
	displayQRcode(totp_uri);

	free(hotp_uri);
	free(totp_uri);
}

int
main(int argc, char * argv[])
{	
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	print_output(issuer, accountName, secret_hex);

	return (0);
}
