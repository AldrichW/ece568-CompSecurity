#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <time.h>

#include "lib/sha1.h"

#define TARGET_HEX_SIZE 20	//20 HEX -> 80 bits bruh bruh
#define TARGET_BYTE_SIZE 10
#define SHA1_UPDATE_LENGTH 64

#define PERIOD 30

#define OPAD 0x5c
#define IPAD 0x36

size_t from_hex_string(char *s, size_t size, uint8_t *binary, size_t max){

  if(2 * max < size){
    return -1;	//Not enough space for the result buffer given the hex size
  }  

  size_t len = size;

  int i;
  int j;
  size_t k;
  for( i = 0, j = 0; j < len; i += 2, j++){
    uint8_t b1, b2;
    b1 = s[i] - '0';
    b2 = s[i+1] - '0';
    binary[ j ] = 16 * b1 + b2;
  }
  for(k = len; k < max; k++){
    binary[ k ] = 0;
  }  

  return len;
}

static int generateHOTP(char *secret_hex, uint8_t *count, int size){
    //Setting up the binary secret K
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
    
    uint8_t secret_byte_data[TARGET_BYTE_SIZE];	//Create a buffer for storing the base 32 encoded string.
    
    uint8_t inner_secret_byte_data[SHA1_UPDATE_LENGTH];
    
    uint8_t outer_secret_byte_data[SHA1_UPDATE_LENGTH];
    
    from_hex_string(secret, TARGET_HEX_SIZE, secret_byte_data, TARGET_BYTE_SIZE);
    
    
    int i;
    for (i = 0; i < TARGET_BYTE_SIZE; i++)
    {
        inner_secret_byte_data[i] = secret_byte_data[i] ^ IPAD;
        outer_secret_byte_data[i] = secret_byte_data[i] ^ OPAD;
    }
    
    for (i =  TARGET_BYTE_SIZE; i < SHA1_UPDATE_LENGTH; i++)
    {
        inner_secret_byte_data[i] = 0x00 ^ IPAD;
        outer_secret_byte_data[i] = 0x00 ^ OPAD;
    }
    
    //Inner Hash
    SHA1_INFO ctx;
    uint8_t sha_inner[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx, (const uint8_t *)inner_secret_byte_data, SHA1_UPDATE_LENGTH); //K XOR ipad
    sha1_update(&ctx,  count, size); //Append counter which is 1
    // keep calling sha1_update if you have more data to hash...
    sha1_final(&ctx, sha_inner);
    
    //Outer Hash
    uint8_t hmac_result[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx, (const uint8_t *)outer_secret_byte_data, SHA1_UPDATE_LENGTH);
    sha1_update(&ctx, (const uint8_t *)sha_inner, SHA1_DIGEST_LENGTH);
    sha1_final(&ctx, hmac_result);
    
    
    
    int offset = hmac_result[19] & 0xf;
    int bin_code = (hmac_result[offset] & 0x7f) << 24 | (hmac_result[offset+1] & 0xff) << 16 | (hmac_result[offset+2] & 0xff) << 8 | (hmac_result[offset+3] & 0xff) ;
    
    int hmacValue = bin_code % 1000000;
    
    return hmacValue;
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
    //Let's start hashing
    uint8_t counter[8];	//create an eight-byte array for the counter
    int i;
    
    counter[7] = 1;
    
    for (i = 0; i < 7; i++)
    {
        counter[i] = 0;
    }
    
    int hmacValue = generateHOTP(secret_hex, counter, 8);

	//printf("%d\n", hmacValue);

	if (hmacValue == atoi(HOTP_string))
	{
		return 1;
	}

	return (0);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{

	int i;
	time_t seconds_past_epoch = time(0);

	//get current period 
	int t =  (int)floor(seconds_past_epoch/PERIOD);

	uint8_t timer[8]; 
	timer[7] = (t >> (8*0)) & 0xff;
	timer[6] = (t >> (8*1)) & 0xff;
	timer[5] = (t >> (8*2)) & 0xff;
	timer[4] = (t >> (8*3)) & 0xff;

	for (i = 0; i < 4; i++)
	{
		timer[i] = 0x00;
	}

	int hmacValue = generateHOTP(secret_hex, timer, 8);

	if (hmacValue == atoi(TOTP_string))
	{
		return 1;
	}

	return (0);
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	HOTP_value = argv[2];
	char *	TOTP_value = argv[3];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(HOTP_value) == 6);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
