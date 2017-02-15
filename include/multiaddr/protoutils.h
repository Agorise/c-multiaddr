#ifndef PROTOUTILS
#define PROTOUTILS

//////////////////////////////////////////////////////////
char ASCII2bits(char ch);

void hex2bin (char *dst, char *src, int len);

char bits2ASCII(char b);

void bin2hex (char *dst, char *src, int len);

//////////////////////////////////////////////////////////
//IPv4 VALIDATOR
#define DELIM "."
 
/* return 1 if string contain only digits, else return 0 */
int valid_digit(char *ip_str);

/* return 1 if IP string is valid, else return 0 */
int is_valid_ipv4(char *ip_str);

//////////////IPv6 Validator
#define MAX_HEX_NUMBER_COUNT 8 

int ishexdigit(char ch);

int is_valid_ipv6(char *str);

uint64_t ip2int(const char * ipconvertint);

char * int2ip(int inputintip);

//I didn't feel another address_bytes_to_string was necesarry sry guys
int bytes_to_string(char** resultzx, const uint8_t * catx,int xbsize);

char * address_string_to_bytes(struct Protocol * xx, const char * abc, size_t getsznow);

int string_to_bytes(uint8_t** finalbytes,size_t* realbbsize, const char * strx, size_t strsize);

#endif
