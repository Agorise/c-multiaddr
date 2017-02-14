#ifndef VARHEXUTILS
#define VARHEXUTILS

#include <stdio.h>
#include <inttypes.h>
#include "varint.h"
#include <stdlib.h>
#include <string.h>
#include "endian.h"
/*uint8_t * encode_big_endian_32(uint32_t ebex32)
{
	uint8_t encbe[10] = {0};
	memcpy(encbe, htobe32(ebex32));
	return encbe;
}*/
int8_t Var_Bytes_Count(uint8_t * countbytesofthis);

uint8_t * Num_To_Varint_64(uint64_t TOV64INPUT); //UINT64_T TO VARINT

uint8_t * Num_To_Varint_32(uint32_t TOV32INPUT); // UINT32_T TO VARINT

uint64_t * Varint_To_Num_64(uint8_t TON64INPUT[60]); //VARINT TO UINT64_t

uint32_t * Varint_To_Num_32(uint8_t TON32INPUT[60]); //VARINT TO UINT32_t

//
char * Int_To_Hex(uint64_t int2hex); //VAR[binformat] TO HEX

uint64_t Hex_To_Int(char * hax);

//
void vthconvert(int size, char * crrz01, uint8_t * xbuf);

char * Var_To_Hex(int realsize, const uint8_t * TOHEXINPUT); //VAR[binformat] TO HEX

uint8_t * Hex_To_Var(char * Hexstr); //HEX TO VAR[BINFORMAT]

//
void convert(char * convert_result, uint8_t * buf);					//Both of them read them properly.

char * Num_To_HexVar_64(uint64_t TOHVINPUT); //UINT64 TO HEXIFIED VAR

void convert2(char * convert_result2, uint8_t * bufhx);

char * Num_To_HexVar_32(uint32_t TOHVINPUT); //UINT32 TO HEXIFIED VAR

uint64_t HexVar_To_Num_64(char * theHEXstring); //HEXIFIED VAR TO UINT64_T

uint32_t HexVar_To_Num_32(char theHEXstring[]); //HEXIFIED VAR TO UINT32_T

#endif
