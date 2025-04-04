/**
@christopherRomo
March 28th, 2025
cromo@uccs.edu
*/

// libraries
#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

// constants
#define BUFFER_SIZE 80

// function declarations
void fgetsRemoveNewLine(char* inputString);

// function to remove newline character from fgets input, taken from CS 2060
void fgetsRemoveNewLine(char* inputString)
{
	// read in string and get string length
	fgets(inputString, BUFFER_SIZE, stdin);
	size_t stringLength = strlen(inputString);

	// replace newline character if there is one
	if (stringLength > 0 && inputString[stringLength - 1] == '\n')
	{
		inputString[stringLength - 1] = '\0';
	}

} // void fgetsRemoveNewLine(char* inputString)

int main(void)
{
	// prompt for message input
	printf("Please input a message to be encrypted: ");
	char message[BUFFER_SIZE];
	fgetsRemoveNewLine(message);

	const char *key = "it's a secret to everybody.";

	unsigned char output[EVP_MAX_MD_SIZE];
	unsigned int output_len;

	// generate hashed message using HMAC
	unsigned char *hmac_output = HMAC(EVP_sha256(), key, strlen(key), (unsigned char *)message, strlen(message), output, &output_len);

	// print the hashed message
	printf("HMAC: ");
	for (unsigned int i = 0; i < output_len; i++)
	{
		printf("%02x", hmac_output[i]);
	}
	printf("\n");

	return 0;
} // int main(void)