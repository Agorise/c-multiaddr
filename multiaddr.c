#include <string.h>
#include "multiaddr/varhexutils.h"
#include "multiaddr/varint.h"
#include "multiaddr/protocols.h"
#include "multiaddr/protoutils.h"
#include "multiaddr/multiaddr.h"

int strpos(char *haystack, char *needle)
{
	char *p = strstr(haystack, needle);
	if (p)
	{
		return p - haystack;
	}
	else
	{
		return -1;   // Not found = -1.
	}
}

/**
 * Construct a new MultiAddress struct
 * @returns an empty MultiAddress struct
 */
struct MultiAddress* multiaddress_new() {
	struct MultiAddress* out = (struct MultiAddress*)malloc(sizeof(struct MultiAddress));
	if (out != NULL) {
		out->bsize = 0;
		out->bytes = NULL;
		out->string = NULL;
	}
	return out;
}

/**
 * construct a new MultiAddress from bytes
 * @param byteaddress the byte array
 * @param size the size of the byte array
 * @returns a new MultiAddress struct filled in, or NULL on error
 */
struct MultiAddress* multiaddress_new_from_bytes(const uint8_t* byteaddress, int size)//Construct new address from bytes
{
	struct MultiAddress* out = multiaddress_new();
	if (out != NULL) {
		if(byteaddress!=NULL)
		{
			out->bytes = malloc(size);
			if (out->bytes == NULL) {
				multiaddress_free(out);
				return NULL;
			}
			memcpy(out->bytes, byteaddress, size);
			if(!bytes_to_string(out->string,byteaddress,size)==1)
			{
				multiaddress_free(out);
				return NULL;
			}
		}
	}
	return out;
}

struct MultiAddress* multiaddress_new_from_string(const char* straddress)//Construct new address from string
{
	struct MultiAddress* out = multiaddress_new();
	if (out != NULL) {
		out->string = malloc(sizeof(straddress) + 1);
		if (out->string == NULL) {
			multiaddress_free(out);
			return NULL;
		}
		strcpy(out->string, straddress);

		if (string_to_bytes(out->bytes, &out->bsize, out->string, sizeof(out->string)) == 0 )
		{
			multiaddress_free(out);
			return NULL;
		}
	}
	return out;
}

void multiaddress_free(struct MultiAddress* in) {
	if (in != NULL) {
		if (in->bytes != NULL)
			free(in->bytes);
		if (in->string != NULL)
			free(in->string);
		free(in);
		in = NULL;
	}
}

/**
 * Copy a multiaddress from one memory location to another
 * @param in the source
 * @param out the destination. NOTE: memory for out should be preallocated
 * @returns true(1) on success, otherwise false(0)
 */
int multiaddress_copy(const struct MultiAddress* in, struct MultiAddress* out) {
	if (in != NULL && out != NULL) {
		// memory allocation
		out->bytes = malloc(in->bsize);
		if (out->bytes != NULL) {
			out->string = malloc(strlen(in->string) + 1);
			if (out->string != NULL) {
				// copy
				out->bsize = in->bsize;
				memcpy(out->bytes, in->bytes, out->bsize);
				strcpy(out->string, in->string);
				return 1;
			} // string allocated
			free(out->bytes);
		} // bytes allocated
	} // good parameters
	return 0;
}

/**
 * Put a string into the MultiAddress and recalculate the bytes
 * @param result the struct
 * @param string the new string
 */
int multiaddress_encapsulate(struct MultiAddress* result, char* string)
{
	if(result != NULL && string != NULL)
	{
		// remove the old values
		if (result->bytes != NULL)
			free(result->bytes);
		result->bytes = NULL;
		result->bsize = 0;
		free(result->string);
		// insert the new values
		result->string = malloc(strlen(string) + 1);
		if (result->string == NULL) {
			multiaddress_free(result);
			return 0;
		}
		strcpy(result->string, string);
		if(string_to_bytes(result->bytes, &result->bsize, result->string, sizeof(result->string)) == 0)
		{
			multiaddress_free(result);
			return 0;
		}
	} else {
		return 0;
	}
	return 1;
}

// not sure what this does
int multiaddress_decapsulate(struct MultiAddress * result, char * srci)
{
	if(result!=NULL && srci!=NULL)
	{
		char * procstr = NULL;
		procstr = result->string;
		int i=0;
		int sz=strlen(procstr);
		char * src = NULL;
		src=srci;
		// change slash to space
		for(i=0;i<sz;i++)
		{
			if(procstr[i] == '/')
			{
				procstr[i]=' ';
			}
		}
		int pos=-1;
		pos=strpos(procstr,src);
		if(pos!=-1)
		{
			// fill rest with 0s
			for(i=pos;i<sz;i++)
			{
				procstr[i] = '\0';
			}
			// replace space with slash
			for(i=0;i<sz;i++)
			{
				if(procstr[i] == ' ')
				{
					procstr[i] = '/';
				}
			}
			return 1;
		}
		else
		{
			return 0;
		}
		return 0;
	}
	else
	{
		return 0;
	}
}

