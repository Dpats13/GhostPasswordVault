#include <Ghost_PV.h>

//Encrypted Password Vault for Personal Use
//Author: Dan Patterson
//Date: 5/5/2019

//globals
static gcry_cipher_hd_t* gcryptHandle = NULL; //gcrypt handle to use library
static struct termios old, new;

//Helper SYS Calls

/* Initialize new terminal i/o settings */
void initTermios(int echo)
{
  tcgetattr(0, &old); /* grab old terminal i/o settings */
  new = old; /* make new settings same as old settings */
  new.c_lflag &= ~ICANON; /* disable buffered i/o */
  if (echo) {
      new.c_lflag |= ECHO; /* set echo mode */
  } else {
      new.c_lflag &= ~ECHO; /* set no echo mode */
  }
  tcsetattr(0, TCSANOW, &new); /* use these new terminal i/o settings now */
}

/* Restore old terminal i/o settings */
void resetTermios(void)
{
  tcsetattr(0, TCSANOW, &old);
}

/* Read 1 character - echo defines echo mode */
char getch_(int echo)
{
  char ch;
  initTermios(echo);
  ch = getchar();
  resetTermios();
  return ch;
}

/* Read 1 character without echo */
char getch(void)
{
  return getch_(0);
}

//Application Code

gcry_cipher_hd_t* gcrypt_init() {
	gcryptHandle = (gcry_cipher_hd_t*) malloc(sizeof(gcry_cipher_hd_t)); //allocate some memory for encrpytion/decryption handle

	if (gcry_cipher_open(gcryptHandle, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0) != 0) { //open an object to perform AES decryption
		printf("Error opening gcryptHandle in decrypt_message()...\n");
		return NULL;
	}

	return gcryptHandle;
}

void printHexBuffer(unsigned char* buf, size_t size) {
	unsigned char str[(5 * size) + 1];
	char tmp[5];
	for (int i = 0; i < size; i++) {
		//printf("buf[%d]: %d\n", i, buf[i]);
		sprintf(tmp, "0x%x ", buf[i]);
		strncat(str, tmp, 5);
	}
	printf("%s\n", str);
}

int encryptPassword(unsigned char* pwDec, unsigned char* pwEnc, uint16_t size, ghost_key_t key, iv_t iv) {
	printf("Attempting to encrypt the password with key: ");
	printHexBuffer(key, sizeof(ghost_key_t));

	//set the random IV for encryption
	if (gcry_cipher_setiv(*gcryptHandle, iv, sizeof(iv_t)) != 0) { //set initialization vector
		printf("Error setting the intitialization vector in encryptPassword()...\n");
		return -1;
	}

	//set the key for encryption
	if (gcry_cipher_setkey(*gcryptHandle, key, sizeof(ghost_key_t)) != 0) {
		printf("Error setting the key in encryptPassword()...\n");
		return -1;
	}

	//encrypt the message
	gcry_error_t error = gcry_cipher_encrypt(*gcryptHandle, pwEnc, size, pwDec, size);
	if (error != 0) {
		printf("Error encrypting the message in encryptPasword()...\n");
		printf("Error: %s\n", gcry_strerror(error));
	 	return -1;
	 }

	 return 0;
}

int decryptPassword(unsigned char* pwEnc, unsigned char* pwDec, uint16_t size, ghost_key_t key, iv_t iv) {
	printf("Attempting to decrypt the password with key: ");
	printHexBuffer(key, sizeof(ghost_key_t));

	if (gcry_cipher_setiv(*gcryptHandle, iv, sizeof(iv_t)) != 0) { //set initialization vector
		printf("Error setting the intitialization vector in decryptPassword()...\n");
		return -1;
	}

	if (gcry_cipher_setkey(*gcryptHandle, key, sizeof(ghost_key_t)) != 0) { //set the key for the object to use for decryption
		printf("Error setting the key in decryptPassword()...\n");
		return -1;
	}

	gcry_error_t error = gcry_cipher_decrypt(*gcryptHandle, pwDec, size, pwEnc, size);
	if (error != 0) {
		printf("Error decrypting the password in decryptPassword()...\n");
		printf("Error: %s\n", gcry_strerror(error));
	 	return -1;
	 }

	 return 0;
}

//helper function to pad a password with null bytes to account for 16-byte alignment requirement by the gcrypt library for AES128 bit encryption
//Params: password, length of password including ending null byte
//Return the number of null bytes appended
int addNullBytes(unsigned char* pw, size_t len) {
		int bytesToAdd = 0;
		if (len == 16 || len == 32 || len == 48) {
			return 0;
		}

		if (len < 16) {
			bytesToAdd = 16 - len;
		}
		else if (len < 32) {
			bytesToAdd = 32 - len;
		}
		else if (len < 48) {
			bytesToAdd = 48 - len;
		}

		int i = 0;
		while (bytesToAdd > 0) {
			pw[len + i] = '\0';
			bytesToAdd--;
			i++;
		}

		return i;
}

//Function to create accounts directory
int createAccountsDirectory() {
	char dirName[8] = "Accounts";
	dirName[8] = '\0';

	//check if directory already exists
	DIR* ghostFolder;
	struct dirent* dir;
	ghostFolder = opendir(".");

	if (ghostFolder) {
		while ((dir = readdir(ghostFolder)) != NULL) {
			if (strcmp(dirName, dir->d_name) == 0) { //folder already exists
				closedir(ghostFolder);
				return 0;
			}
		}
	}
	else {
		printf("Error accessing current directory, exiting...\n");
		return -1;
	}

	//Accounts folder doesn't exist, so create it
	if (mkdir("./Accounts", S_IRUSR | S_IWUSR) == 0) {
		return 0;
	}
	else {
		perror("mkdir");
		return -1;
	}
}

void getMasterPassword(unsigned char* masterPW) {
	int i = 0;
	printf("Enter Your Master Password: ");
	while (i <= 47) {
		masterPW[i] = getch();
		if (masterPW[i] == 10) {
			break;
		}
		else {
			printf("*");
			i++;
		}
	}
	masterPW[i] = '\0';
	printf("\n");
}

//Btes are serialized and saved to a file in this order:
//iv, pwEncSize, pwEnc, usernameSize, username decrypted
int saveAccount(unsigned char* fileName, unsigned char* username, unsigned char* pwDec) {
	unsigned char masterPW[48];
	unsigned char filePath[11 + strlen(fileName) + 1];
	strncpy(filePath, "./Accounts/", 11);
	filePath[11] = '\0';
	strcat(filePath, fileName);

	int bytesAdded = addNullBytes(pwDec, strlen(pwDec) + 1);
	int nullBytes = bytesAdded + 1;

	unsigned char* pwEnc = malloc(strlen(pwDec)+nullBytes);

	getMasterPassword(masterPW);

	ghost_key_t key;
	if ((genKeyFromPassword(masterPW, key)) != 0) {
		printf("Error generating key for encryption\n");
		free(pwEnc);
		return -1;
	}

	iv_t iv;
	gcry_create_nonce(iv, sizeof(iv_t));

	if (encryptPassword(pwDec, pwEnc, strlen(pwDec)+nullBytes, key, iv) != 0) {
		printf("Error encrypting password\n");
		free(pwEnc);
		return -1;
	}

	printf("Attempting to save account...\n");

	unsigned int pwEncSize = strlen(pwDec) + nullBytes;

	//serialize a buffer for file writing
	unsigned int totalSize = sizeof(iv_t) + 1 + pwEncSize + 1 + strlen(username) + 1;
	unsigned char* buf = (unsigned char*) malloc(totalSize * sizeof(char));
	memcpy(buf, iv, sizeof(iv_t));
	buf[16] = strlen(pwDec) + nullBytes;
	memcpy(buf+17, pwEnc, pwEncSize);
	buf[17 + pwEncSize] = strlen(username) + 1;
	memcpy(buf + 17 + pwEncSize + 1, username, strlen(username) + 1);

	//open and write to the designated file
	strcat(filePath, ".txt");
	FILE* fp = fopen(filePath, "w");

	if (fp == NULL) {
		printf("Error opening file %s\n", filePath);
		free(pwEnc);
		free(buf);
		return -1;
	}

	size_t bytesWritten = fwrite(buf, sizeof(char), totalSize, fp);
	if (bytesWritten != totalSize) {
		printf("Not all data was written to the file correctly\n");
		fclose(fp);
		free(pwEnc);
		free(buf);
		return -1;
	}

	fclose(fp);
	free(pwEnc);
	free(buf);
	return 0;
}

int saveAccountInit() {
	unsigned char fileName[50];
	unsigned char username[50];
	unsigned char pw[48];

	printf("Enter Account Type: ");
	fgets(fileName, 50, stdin);
	strtok(fileName, "\n");

	printf("Enter Your Username for the Account: ");
	fgets(username, 50, stdin);
	strtok(username, "\n");

	printf("Enter Your Password for the Account: ");
	fgets(pw, 48, stdin);
	strtok(pw, "\n");

	if (saveAccount(fileName, username, pw) != 0) {
		printf("Error saving account, exiting...\n");
		return -1;
	}

	printf("Account saved successfully!\n");
	return 0;
}

int retrieveAccount(unsigned char* fileName, unsigned char* username, unsigned char* pwDec) {
	iv_t iv;
	ghost_key_t key;
	unsigned char masterPW[48];

	getMasterPassword(masterPW);

	if ((genKeyFromPassword(masterPW, key)) != 0) {
		printf("Error generating key for decryption\n");
		return -1;
	}

	FILE* fp = fopen(fileName, "r");

	if (fp == NULL) {
		printf("Error opening file %s\n", fileName);
	}

	printf("Attempting to retrieve account...\n\n");

	size_t bytesRead = fread(iv, sizeof(char), sizeof(iv_t), fp);
	if (bytesRead != sizeof(iv_t)) {
		printf("Not all bytes of the Initialization Vector were read.\n");
		return -1;
	}

	uint8_t pwEncSize = 0;
	bytesRead = fread(&pwEncSize, sizeof(char), sizeof(uint8_t), fp);
	if (bytesRead != sizeof(uint8_t)) {
		printf("Not all bytes of the encrypted password's size were read.\n");
		return -1;
	}

	unsigned char* pwEnc = (unsigned char*) malloc(pwEncSize * sizeof(char));
	bytesRead = fread(pwEnc, sizeof(char), pwEncSize, fp);
	if (bytesRead != pwEncSize) {
		printf("Not all bytes of the encrypted password were read.\n");
		free(pwEnc);
		return -1;
	}

	uint8_t usernameSize = 0;
	bytesRead = fread(&usernameSize, sizeof(char), sizeof(uint8_t), fp);
	if (bytesRead != sizeof(uint8_t)) {
		printf("Not all bytes of the username's size were read.\n");
		free(pwEnc);
		return -1;
	}

	bytesRead = fread(username, sizeof(char), usernameSize, fp);
	if (bytesRead != usernameSize) {
		printf("Not all bytes of the username were read.\n");
		free(pwEnc);
		return -1;
	}

	if (decryptPassword(pwEnc, pwDec, pwEncSize, key, iv) != 0) {
		free(pwEnc);
		return -1;
	}

	printf("Username: %s\n", username);
	printf("Password: %s\n\n", pwDec);
	free(pwEnc);
	return 0;
}


int retrieveAccountInit() {
	unsigned char username[50];
	unsigned char pw[48];
	unsigned char filePath[50] = "./Accounts/";
	filePath[11] = '\0';

	printf("Enter Account Type: ");
	fgets(filePath + 11, 38, stdin);
	strtok(filePath, "\n");

	strcat(filePath, ".txt");

	if (retrieveAccount(filePath, username, pw) != 0) {
		printf("Error retrieving account, exiting...\n");
		return -1;
	}

	printf("Account retrieved successfully!\n");
	return 0;
}


int main(int argc, char** argv) {
	//initialize gcrypt
	printf("Initializing encryption library...\n");
	gcryptHandle = gcrypt_init();
	if (gcryptHandle == NULL) {
		printf("Error initializing gcrypt library... Exiting...\n");
		return -1;
	}
	printf("Encryption Library Initalized Successfully!\n\n");

	if (createAccountsDirectory() != 0) {
		return -1;
	}

	printf("Welcome to Ghost Password Vault!\n\n");

	uint8_t using = 1;
	char mode = ' ';
	while(using) {
		printf("Enter (s) to save an account or (r) to retrieve an account or (q) to quit: ");
		mode = getc(stdin);
		getc(stdin); //clear enter character
		printf("\n");
		switch(mode) {
			case 's':
				if (saveAccountInit() != 0) {
					return -1;
				}
				break;
			case 'r':
				if(retrieveAccountInit() != 0) {
					return -1;
				}
				break;
			case 'q':
				using = 0;
				break;
			default:
				printf("Not a valid entry, try again...\n");
		}
	}

	//close the gcrypt handle
	gcry_cipher_close(*gcryptHandle);
	free(gcryptHandle); //free the memory
	return 0;

}

int genKeyFromPassword(unsigned char* pw, ghost_key_t key) {
	gcry_md_hd_t sha256;
	gcry_md_open(&sha256, GCRY_MD_SHA256, 0);
	gcry_md_write(sha256, pw, strlen(pw));
	memcpy(key, gcry_md_read(sha256, GCRY_MD_SHA256), sizeof(ghost_key_t));
	gcry_md_close(sha256);
	return 0;

}
