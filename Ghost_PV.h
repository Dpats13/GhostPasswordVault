#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <gcrypt.h>
#include <dirent.h>
#include <sys/stat.h>
#include <termios.h>

#define ACCOUNTS_PATH ./Accounts

typedef uint8_t ghost_key_t[16];
typedef uint8_t iv_t[16];

int getRandomData(unsigned char* buffer, size_t len);

int encryptPassword(unsigned char* pwDec, unsigned char* pwEnc, uint16_t size, ghost_key_t key, iv_t iv);

int decryptPassword(unsigned char* pwEnc, unsigned char* pwDec, uint16_t size, ghost_key_t key, iv_t iv);

int saveAccount(unsigned char* fileName, unsigned char* username, unsigned char* pwDec);

int retrieveAccount(unsigned char* fileName, unsigned char* username, unsigned char* pwDec);

int genKeyFromPassword(unsigned char* pw, ghost_key_t key);
