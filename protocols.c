#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "multiaddr/protocols.h"
#include "multiaddr/varhexutils.h"

int CNT_PROTOCOLNUM=0;

struct protocol *protocol_P; //Pointer for holding multiple structures

int protocol_REMOVE_id(int remid)//Function to remove & shift back all data, sort of like c++ vectors.
{

	if(remid < CNT_PROTOCOLNUM && remid >= 0&&CNT_PROTOCOLNUM!=0) //Checking to see if remid actually exists.
	{
		for(int i=remid; i<CNT_PROTOCOLNUM-1; ++i) //While i < num of registered protocols //Needs to be tested that -1 is for valgrind debugging
		{
			strcpy((protocol_P+i)->hexcode, (protocol_P+i+1)->hexcode); //shift memory to the user we want to remove.
			(protocol_P+i)->deccode = (protocol_P+i+1)->deccode;       	//Same as above
			(protocol_P+i)->size = (protocol_P+i+1)->size; 				//Same as above
			strcpy((protocol_P+i)->name, (protocol_P+i+1)->name);		//Same as above
		}//Overwriting user done. Time to get rid of that extra memory.
		protocol_P = (struct protocol*) realloc(protocol_P, (CNT_PROTOCOLNUM-1) * sizeof(struct protocol));
		//Memory erased,
		CNT_PROTOCOLNUM--; //Since the record no longer exists, we should decrease the ammount of users.
		return 1; //Purely for error checking, in case someone ever wants it/
	}	//1 = Success
	else
	{
		if(CNT_PROTOCOLNUM == 0)
		{
			perror("ERROR: 0 PROTOCOLS... Did you load protocols?");
		}
		else
		{
			perror("ERROR: No such protocol!");
		}
		return 0;
	}
}
void unload_protocols()
{
	free(protocol_P);
	CNT_PROTOCOLNUM=0;
}
void load_protocols()
{
	FILE *FPROC_POINT; //File pointer.
	FPROC_POINT = fopen("proto-dat", "r");//Opening proto-dat Or protocols.csv, I just formatted it to my liking.
	if(FPROC_POINT != NULL) //While pointer is not null.
	{
		char W_BUFF[20] = "\0";//Char array to parse file.
		for(int i=0; fscanf(FPROC_POINT, "%s", W_BUFF) != EOF; i++) // Scanning file and incrementing for processing.
		{
			switch(i)
			{
				case 0: //First word - HEXCODE
				{
					//ADD MEMORY FOR NEW PROTOCOL
					if(CNT_PROTOCOLNUM==0) //If there are no registered protocols yet, allocate memory to pointer.
					{
						protocol_P = (struct protocol*) malloc (sizeof(struct protocol));
					}
					else //Reallocate memory to fit one more protocol
					{
						protocol_P = (struct protocol*) realloc(protocol_P, (CNT_PROTOCOLNUM+1) * sizeof(struct protocol));
					}
					strcpy((protocol_P+CNT_PROTOCOLNUM)->hexcode, W_BUFF);	//Copy word to structure at hexcode A hexcode is a string so we keep it as such
					break;
				}
				case 1://Second word - DECCODE
				{
					(protocol_P+CNT_PROTOCOLNUM)->deccode= atoi(W_BUFF);	//Copy word to structure at deccode after converting it to int.
					break;
				}
				case 2://Third word - SIZE
				{
					(protocol_P+CNT_PROTOCOLNUM)->size= atoi(W_BUFF);		//Copy word to structure at size after converting it to int.
					break;
				}
				case 3://Fourth word - NAME
				{
					strcpy((protocol_P+CNT_PROTOCOLNUM)->name, W_BUFF); 	//Copy word to structure at name // String
					i=-1;
					CNT_PROTOCOLNUM++;
					break;
				}
				default:
				{
					printf("HOUSTON WE HAVE A BIG PROBLEM!!!!\nPROTOCOLS.H-REACHED DEFAULT CASE IN READING FILE!\nREPORT TO SYSTEMS ADMIN!\n");
					break;
				}
			}
		}
		fclose(FPROC_POINT);
		protocol_REMOVE_id(0);
	}
	else
	{
		perror("Fatal Error:");
	}
}
struct protocol * proto_with_name(char proto_w_name[]) //Search for protocol with inputted name
{

	for(int i=0; i<CNT_PROTOCOLNUM; i++)
	{
		if(strcmp(proto_w_name, (protocol_P+i)->name) == 0)
		{
			return (protocol_P+i);
		}
	}
	return NULL;
}
struct protocol * proto_with_deccode(int proto_w_deccode) //Search for protocol with inputted deccode
{
	for(int i=0; i<CNT_PROTOCOLNUM; i++)
	{
		if((protocol_P+i)->deccode == proto_w_deccode)
		{
			return (protocol_P+i);
		}
	}
	return NULL;
}
void pp() //Purely for debugging purposes, prints the entire loaded protocols.
{
	for(int i=0;i<CNT_PROTOCOLNUM;i++)
	{
		if(i>=9)
		{printf("=========== ~%d~ ===========\n", i+1);}
		else
		{printf("=========== ~0%d~ ===========\n", i+1);}
		printf(">> HEX-CODE: %s\n", (protocol_P+i)->hexcode);
		printf(">> DEC-CODE: %d\n", (protocol_P+i)->deccode);
		printf(">> SIZE: %d\n", (protocol_P+i)->size);
		printf(">> NAME: %s\n", (protocol_P+i)->name);
	}
	printf("----------------------------\n");
	printf("TOTAL PROTOCOLS: %d\n",CNT_PROTOCOLNUM);
}
void protocols_with_string(char * meee,int sizi) // NOT FINISHED, DO NOT USE!
{
	int finalsize = 0;

	if(!isalnum(meee[sizi-1]) && !isalnum(meee[sizi-1]))
	{
		//Everything is alright, it's nul terminated!;
		finalsize = sizi;
	}
	else
	{
		//Well houston we have a problem.
		finalsize = sizi+2;
	}
	char mestring[finalsize];
	strcpy(mestring, meee);
	if(sizi!=finalsize)
	{
		strcpy(mestring,"\0");
	}

	char * words[50] = { NULL };
	int atword = 0;
	int mem = 0;
	for(int i=0; i<sizeof(mestring)-2; i++)
	{
		if(mestring[i] == '/')
		{
			printf("NEW WORD!\n");
			atword++;
			int currentsize = 0;
			for(int j = i+1; mestring[j] != '/' && j < sizeof(mestring)-2; j++)
			{
				currentsize++;
			}
			char haay[20];
			int lesbo = 0;
			for(int x = i+1; x<sizeof(mestring)-2; x++)
			{
				if(mestring[x] == '/')
				{
					break;
				}
				haay[lesbo] = mestring[x];
				lesbo++;
			}
			words[atword-1] = (char *) malloc(currentsize+2);
			strcpy(words[atword-1], haay);
			bzero(haay,20);
		}
	}
	printf("Result:%s\n", words[0]);
	for(int mm=0; mm < 50; mm++)
	{
		if(words[mm])
		{
			free(words[mm]);
		}
	}
}
