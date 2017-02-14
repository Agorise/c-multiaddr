#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <inttypes.h>
#include <ctype.h>
#include "multiaddr/base58.h"
#include "multiaddr/varhexutils.h"
#include "multiaddr/protocols.h"
#include "multiaddr/protoutils.h"

//////////////////////////////////////////////////////////
char ASCII2bits(char ch) {
   if (ch >= '0' && ch <= '9') {
      return (ch - '0');
   } else if (ch >= 'a' && ch <= 'z') {
      return (ch - 'a') + 10;
   } else if (ch >= 'A' && ch <= 'Z') {
      return (ch - 'A') + 10;
   }
   return 0; // fail
}

void hex2bin (char *dst, char *src, int len)
{
    while (len--) {
        *dst    = ASCII2bits(*src++) << 4; // higher bits
        *dst++ |= ASCII2bits(*src++);      // lower  bits
    }
}

char bits2ASCII(char b) {
   if (b >= 0 && b < 10) {
      return (b + '0');
   } else if (b >= 10 && b <= 15) {
      return (b - 10 + 'a');
   }
   return 0; // fail
}

void bin2hex (char *dst, char *src, int len)
{
    while (len--) {
        *dst++ = bits2ASCII((*src >> 4) & 0xf);    // higher bits
        *dst++ = bits2ASCII(*src++ & 0xf); // lower  bits
    }
    *dst = '\0';
}
//////////////////////////////////////////////////////////
//IPv4 VALIDATOR
#define DELIM "."

/* return 1 if string contain only digits, else return 0 */
int valid_digit(char *ip_str)
{
	int err = 0;
    while (*ip_str) {
        if (*ip_str >= '0' && *ip_str <= '9')
            ++ip_str;
        else
            return 0;
    }
    return 1;
}

/* return 1 if IP string is valid, else return 0 */
int is_valid_ipv4(char *ip_str)
{
    int i, num, dots = 0;
    char *ptr;
	int err=0;
    if (ip_str == NULL)
        err = 1;

    // See following link for strtok()
    // http://pubs.opengroup.org/onlinepubs/009695399/functions/strtok_r.html
    ptr = strtok(ip_str, DELIM);

    if (ptr == NULL)
        err = 1;

    while (ptr)
	{

        /* after parsing string, it must contain only digits */
        if (!valid_digit(ptr))
            err = 1;

        num = atoi(ptr);

        /* check for valid IP */
        if (num >= 0 && num <= 255) {
            /* parse remaining string */
            ptr = strtok(NULL, DELIM);
            if (ptr != NULL)
                ++dots;
        } else
            err = 1;
    }

    /* valid IP string must contain 3 dots */
    if (dots != 3)
	{
        err = 1;
	}
	if(err == 0)
	{
    return 1;
	}
	else
	{
		return 0;
	}
}


//////////////IPv6 Validator
#define MAX_HEX_NUMBER_COUNT 8

int ishexdigit(char ch)
{
   if((ch>='0'&&ch<='9')||(ch>='a'&&ch<='f')||(ch>='A'&&ch<='F'))
      return(1);
   return(0);
}

int is_valid_ipv6(char *str)
{
   int hdcount=0;
   int hncount=0;
   int err=0;
   int packed=0;

   if(*str==':')
   {
      str++;
      if(*str!=':')
         return(0);
      else
      {
         packed=1;
         hncount=1;
         str++;

         if(*str==0)
            return(1);
      }
   }

   if(ishexdigit(*str)==0)
   {
      return(0);
   }

   hdcount=1;
   hncount=1;
   str++;

   while(err==0&&*str!=0)
   {
      if(*str==':')
      {
         str++;
         if(*str==':')
         {
           if(packed==1)
              err=1;
           else
           {
              str++;

          if(ishexdigit(*str)||*str==0&&hncount<MAX_HEX_NUMBER_COUNT)
          {
             packed=1;
             hncount++;

             if(ishexdigit(*str))
             {
                if(hncount==MAX_HEX_NUMBER_COUNT)
                {
                   err=1;
                } else
                {
                   hdcount=1;
                   hncount++;
                   str++;
                }
             }
          } else
          {
             err=1;
          }
       }
    }
	else
    {
           if(!ishexdigit(*str))
           {
              err=1;
           } else
           {
              if(hncount==MAX_HEX_NUMBER_COUNT)
              {
                 err=1;
              } else
              {
                  hdcount=1;
                  hncount++;
                  str++;
              }
           }
        }
     }
	 else
     {
        if(ishexdigit(*str))
        {
           if(hdcount==4)
              err=1;
           else
           {
              hdcount++;
              str++;
           }
         } else
            err=1;
     }
   }

   if(hncount<MAX_HEX_NUMBER_COUNT&&packed==0)
      err=1;

    return(err==0);
}
uint64_t ip2int(const char * ipconvertint)
{
	uint64_t final_result =0;
	char * iproc;
	int ipat1=0;
	int ipat2=0;
	int ipat3=0;
	int ipat4=0;
	char ip[16];
	strcpy(ip, ipconvertint);
	iproc = strtok (ip,".");
	for(int i=0; i<4;i++)
	{
		switch(i)
		{
			case 0:
			{
				ipat1 = atoi(iproc);
				break;
			}
			case 1:
			{
				ipat2 = atoi(iproc);
				break;
			}
			case 2:
			{
				ipat3 = atoi(iproc);
				break;
			}
			case 3:
			{
				ipat4 = atoi(iproc);
				break;
			}
			default:
			{
				printf("Somebody misplaced an int\n");
				break;
			}
		}
		iproc = strtok (NULL,".");
	}
	final_result =  ((ipat1*pow(2,24))+(ipat2*pow(2,16))+(ipat3*pow(2,8))+ipat4*1);
	return final_result;
}
char * int2ip(int inputintip)
{
	uint32_t ipint = inputintip;
	static char xxx_int2ip_result[16] = "\0";
	bzero(xxx_int2ip_result,16);
	uint32_t ipint0 = (ipint >> 8*3) % 256;
	uint32_t ipint1 = (ipint >> 8*2) % 256;
	uint32_t ipint2 = (ipint >> 8*1) % 256;
	uint32_t ipint3 = (ipint >> 8*0) % 256;
	sprintf(xxx_int2ip_result, "%d.%d.%d.%d", ipint0,ipint1,ipint2,ipint3);
	return xxx_int2ip_result;
}
//I didn't feel another address_bytes_to_string was necesarry sry guys
int bytes_to_string(char * resultzx, const uint8_t* catx,int xbsize)
{
	bzero(resultzx,800);
	uint8_t * bytes = NULL;
	int size = 0;
	size = xbsize;
	load_protocols();
	char hex[xbsize*2];
	bzero(hex,xbsize*2);
	strcat(hex,Var_To_Hex(size, catx));
	//Positioning for memory jump:
	int lastpos = 0;
	char pid[3];
	//Process Hex String
	NAX:
	//Stage 1 ID:
	if(lastpos!=0)
	{
		lastpos+1;
	}
	pid[0] = hex[lastpos];
	pid[1] = hex[lastpos+1];
	pid[2] = '\0';
	if(lastpos == 0)
	{
		load_protocols();
	}
	if(proto_with_deccode(Hex_To_Int(pid)))
	{
//////////Stage 2: Address
		struct protocol * PID;
		PID = NULL;
		PID = proto_with_deccode(Hex_To_Int(pid));
		if(strcmp(PID->name,"ipfs")!=0)
		{
			lastpos = lastpos+2;
			char address[(PID->size/4)+1];
			bzero(address,(PID->size/4)+1);
			address[(PID->size/4)]='\0';
			int x=0;
			//printf("\nHEX TO DECODE: %s\n",hex);
			for(int i = lastpos;i<(PID->size/4)+lastpos;i++)
			{
				address[x] = hex[i];
				//printf("HEX[%d]=%c\n",i,hex[i]);
				x++;
			}
	//////////Stage 3 Process it back to string
			//printf("Protocol: %s\n", PID->name);
			//printf("Address : %s\n", address);
			lastpos= lastpos+(PID->size/4);
			//printf("lastpos: %d",lastpos);

	//////////Address:
			//Keeping Valgrind happy
			char name[30];
			bzero(name,30);
			strcpy(name, PID->name);
			//
			strcat(resultzx, "/");
			strcat(resultzx, name);
			strcat(resultzx, "/");
			if(strcmp(name, "ip4")==0)
			{
				strcat(resultzx,int2ip(Hex_To_Int(address)));
			}
			else if(strcmp(name, "tcp")==0)
			{
				char a[5];
					sprintf(a,"%lu",Hex_To_Int(address));
					strcat(resultzx,a);
			}
			else if(strcmp(name, "udp")==0)
			{
				char a[5];
				sprintf(a,"%lu",Hex_To_Int(address));
				strcat(resultzx,a);
			}
			//printf("Address(hex):%s\n",address);
			//printf("TESTING: %s\n",resultzx);
	/////////////Done processing this, move to next if there is more.
			if(lastpos<size*2)
			{
				goto NAX;
			}
		}
		else//IPFS CASE
		{

			lastpos = lastpos + 4;
			//FETCHING SIZE OF ADDRESS
			char prefixedvarint[3];
			bzero(prefixedvarint,3);
			int pvi;
			pvi=0;
			for(int i=lastpos-2;i<lastpos;i++)
			{
				prefixedvarint[pvi] = hex[i];
				pvi++;
			}
			int addrsize;
			addrsize = HexVar_To_Num_32(prefixedvarint);
			unsigned char IPFS_ADDR[addrsize+1];
			bzero(IPFS_ADDR,addrsize+1);
			int IPFS_PARSE;
			IPFS_PARSE = 0;
			for(int i = lastpos;i<lastpos+addrsize;i++)
			{
				IPFS_ADDR[IPFS_PARSE] = hex[i];
				//printf("\nIPFS_ADDR[%d] = %c\n\n",IPFS_PARSE,hex[i]);
				IPFS_PARSE++;
			}
			unsigned char addrbuf[strlen(IPFS_ADDR)/2];
			bzero(addrbuf,strlen(IPFS_ADDR)/2);
			memcpy(addrbuf,Hex_To_Var(IPFS_ADDR),sizeof(addrbuf));
			size_t rezbuflen = strlen(IPFS_ADDR);
			unsigned char rezultat[rezbuflen];
			bzero(rezultat,rezbuflen);
			unsigned char * pointyaddr = NULL;
			pointyaddr = rezultat;
			int returnstatus = 0;
			returnstatus = multiaddr_encoding_base58_encode(addrbuf, sizeof(addrbuf), &pointyaddr, &rezbuflen);
			if(returnstatus == 0)
			{
				printf("\nERROR!!!!!\n");
				return 0;
			}
			strcat(resultzx, "/");
			strcat(resultzx, PID->name);
			strcat(resultzx, "/");
			strcat(resultzx, rezultat);
		}
	}
	strcat(resultzx, "/");
	unload_protocols();

}
//

char * address_string_to_bytes(struct protocol * xx, const char * abc,size_t getsznow)
{
	static char astb__stringy[800] = "\0";
	bzero(astb__stringy,800);
	int code = 0;
	code = xx->deccode;
	switch(code)
	{
		case 4://IPv4
		{
			char testip[16] = "\0";
			bzero(testip,16);
			strcpy(testip,abc);
			if(is_valid_ipv4(testip)==1)
			{
				uint64_t iip = ip2int(abc);
				strcpy(astb__stringy,Int_To_Hex(iip));
				xx = NULL;
				return astb__stringy;
			}
			else
			{
				return "ERR";
			}
			break;
		}
		case 41://IPv6 Must be done
		{
			return "ERR";
			break;
		}
		case 6: //Tcp
		{
			if(atoi(abc)<65536&&atoi(abc)>0)
			{
				static char himm_woot[5] = "\0";
				bzero(himm_woot, 5);
				strcpy(himm_woot, Int_To_Hex(atoi(abc)));
				if(himm_woot[2] == '\0')
				{//manual switch
					char swap0='0';
					char swap1='0';
					char swap2=himm_woot[0];
					char swap3=himm_woot[1];
					himm_woot[0] = swap0;
					himm_woot[1] = swap1;
					himm_woot[2] = swap2;
					himm_woot[3] = swap3;
				}
				else if(himm_woot[3] == '\0')
				{
					char swap0='0';
					char swap1=himm_woot[0];
					char swap2=himm_woot[1];
					char swap3=himm_woot[2];
					himm_woot[0] = swap0;
					himm_woot[1] = swap1;
					himm_woot[2] = swap2;
					himm_woot[3] = swap3;
				}
				himm_woot[4]='\0';
				return himm_woot;
			}
			else
			{
				return "ERR";
			}
			break;
		}
		case 17: //Udp
		{
			if(atoi(abc)<65536&&atoi(abc)>0)
			{
				static char himm_woot2[5] = "\0";
				bzero(himm_woot2, 5);
				strcpy(himm_woot2, Int_To_Hex(atoi(abc)));
				if(himm_woot2[2] == '\0')
				{//Manual Switch2be
					char swap0='0';
					char swap1='0';
					char swap2=himm_woot2[0];
					char swap3=himm_woot2[1];
					himm_woot2[0] = swap0;
					himm_woot2[1] = swap1;
					himm_woot2[2] = swap2;
					himm_woot2[3] = swap3;
				}
				else if(himm_woot2[3] == '\0')
				{//Manual switch
					char swap0='0';
					char swap1=himm_woot2[0];
					char swap2=himm_woot2[1];
					char swap3=himm_woot2[2];
					himm_woot2[0] = swap0;
					himm_woot2[1] = swap1;
					himm_woot2[2] = swap2;
					himm_woot2[3] = swap3;
				}
				himm_woot2[4]='\0';
				return himm_woot2;
			}
			else
			{
				return "ERR";
			}
			break;
		}
		case 33://dccp
		{
			return "ERR";
			break;
		}
		case 132://sctp
		{
			return "ERR";
			break;
		}
		case 301://udt
		{
			return "ERR";
			break;
		}
		case 302://utp
		{
			return "ERR";
			break;
		}
		case 42://IPFS - !!!
		{


			char * x_data = NULL;
			x_data = (char*)abc;
			size_t x_data_length = strlen(x_data);
			size_t result_buffer_length = multiaddr_encoding_base58_decode_size((unsigned char*)x_data);
			unsigned char result_buffer[result_buffer_length];
			unsigned char* ptr_to_result = result_buffer;
			memset(result_buffer, 0, result_buffer_length);
			// now get the decoded address
			int return_value = multiaddr_encoding_base58_decode(x_data, x_data_length, &ptr_to_result, &result_buffer_length);
			if (return_value == 0)
			{
				return "ERR";
			}
			// throw everything in a hex string so we can debug the results
			static char returning_result[300];
			bzero(returning_result,300);
			char ADDR_ENCODED[300];
			bzero(ADDR_ENCODED,300);
			int ilen = 0;
			bzero(returning_result,300);
			for(int i = 0; i < result_buffer_length; i++)
			{
				// get the char so we can see it in the debugger
				unsigned char c = ptr_to_result[i];
				char miu[3];
				bzero(miu, 3);
				miu[3] = '\0';
				sprintf(miu,"%02x", c);

				strcat(ADDR_ENCODED, miu);
			}
			ilen = strlen(ADDR_ENCODED);
			char prefixed[3];
			strcpy(prefixed,Num_To_HexVar_32(ilen));
			prefixed[3] = '\0';
			strcat(returning_result, prefixed);
			strcat(returning_result, ADDR_ENCODED);
			//printf("ADDRESS: %s\nSIZEADDR: %d\n",ADDR_ENCODED,ilen);
			//printf("NOW DECODED VARINT: %d", HexVar_To_Num_32(prefixed));
			return returning_result;
			break;
		}
		case 480://http
		{
			return "ERR";
			break;
		}
		case 443://https
		{
			return "ERR";
			break;
		}
		case 477://ws
		{
			return "ERR";
			break;
		}
		case 444://onion
		{
			return "ERR";
			break;
		}
		case 275://libp2p-webrtc-star
		{
			return "ERR";
			break;
		}
		default:
		{
			printf("NO SUCH PROTOCOL!\n");
			return "ERR";
			break;
		}
	}
}

/**
 * convert a string address into bytes
 * @param finalbytes the destination
 * @param realbbsize the ultimate size of the destination
 * @param strx the incoming string
 * @param strsize the string length
 */
int string_to_bytes(uint8_t * finalbytes, size_t* realbbsize, char * strx, size_t strsize)
{
	if(strx[0] != '/')
	{
		printf("Error, must start with '/'\n");
		return 0;
	}
	//Getting total words
	int totalwords = 0;
	char* totp;
	char totalwordstest[strsize + 1];
	bzero(totalwordstest,strsize + 1);
	strcat(totalwordstest, strx);
	totp = strtok(totalwordstest, "/");
	while(totp != NULL)
	{
		totp = strtok (NULL, "/");
		totalwords++;
	}
	//Initializing variables to store our processed HEX in:
	int malf=0; //In case something goes wrong this will be 1.
	char processed[800];//HEX CONTAINER
	bzero(processed,800);
	//Now Setting up variables for calculating which is the first
	//and second word:
	int firstorsecond = 1; //1=Protocol && 2 = Address
	char pstring[strsize + 1];//We do not want to harm the initial string.
	bzero(pstring,strsize + 1);
	strcat(pstring,strx);
	//Starting to extract words and process them:
	char * wp;
	char * end;
	wp=strtok_r(pstring,"/",&end);
	load_protocols();
	struct protocol * protx;
	while(wp)
	{
		if(firstorsecond==1)//This is the Protocol
		{
			if(proto_with_name(wp))
			{
				protx=proto_with_name(wp);
				//printf("PROTOCOL: %s\n",protx->name);
				strcat(processed, Int_To_Hex(protx->deccode));
				firstorsecond=2;//Since the next word will be an address
			}
			else
			{
				printf("\nNo such protocol!\n\n");
				malf=1;
				break;
			}
		}
		else//This is the address
		{
			//printf("ADDRESS: %s\n",wp);
			if(address_string_to_bytes(protx, wp,strlen(wp)) == "ERR")
			{
				malf = 1;
				//printf("\n\nTRIGGERED!!!!!!!!!!!!!!!!!!!!!!!\n\n");
			}
			else
			{
				strcat(processed,address_string_to_bytes(protx, wp,strlen(wp)));
				//printf("Addressinbytes: %s\n",address_string_to_bytes(protx, wp,strlen(wp)));
			}
			protx=NULL;//Since right now it doesn't need that assignment anymore.
			firstorsecond=1;//Since the next word will be an protocol
		}
		wp=strtok_r(NULL,"/",&end);
	}
	protx=NULL;
	unload_protocols();
	//printf("Processed contains: %s \n",processed);

	if(malf==1)
	{
		return 0;
	}
	else
	{
		bzero(finalbytes,400);
		//printf("XXX: %s\n",xxx);
		memcpy(finalbytes, Hex_To_Var(processed), 400);
		realbbsize[0] = 0;
		for(int i=0;i<400;i++)
		{
			if(finalbytes[i])
			{
				realbbsize[0]++;
			}
		}
		return 1;
	}
}

