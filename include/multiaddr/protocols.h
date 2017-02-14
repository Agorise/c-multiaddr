#ifndef PROTOCOLS
#define PROTOCOLS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include "varhexutils.h"

struct protocol
{
	char hexcode[21];
	int deccode;
	int size;
	char name[30];
};

struct protocol *protocol_P; //Pointer for holding multiple structures

int protocol_REMOVE_id(int remid); //Function to remove & shift back all data, sort of like c++ vectors.

void unload_protocols();

void load_protocols();

struct protocol * proto_with_name(char proto_w_name[]); //Search for protocol with inputted name

struct protocol * proto_with_deccode(int proto_w_deccode); //Search for protocol with inputted deccode

void pp(); //Purely for debugging purposes, prints the entire loaded protocols.

void protocols_with_string(char * meee,int sizi); // NOT FINISHED, DO NOT USE!

#endif
