#pragma once

#include "multiaddr/multiaddr.h"

int test_new_from_string() {
	struct MultiAddress* a = multiaddress_new_from_string("/ip4/127.0.0.1/tcp/8080/");
	printf("Number of Bytes: %lu, Bytes: ", a->bsize);
	for(int i = 0; i < a->bsize; i++) {
		printf("%02x ", a->bytes[i]);
	}
	printf(" End of bytes\n");
	multiaddress_free(a);
	return 1;
}

int test_full() {
	char addrstr[100];
	strcpy(addrstr,"/ip4/192.168.1.1/tcp/8080/");
	printf("INITIAL: %s\n",addrstr);
	struct MultiAddress* a;
	a= multiaddress_new_from_string(addrstr);
	printf("TEST BYTES: %s\n",Var_To_Hex(a->bsize, a->bytes));

	//Remember, Decapsulation happens from right to left, never in reverse!

	printf("A STRING:%s\n",a->string);
	multiaddress_encapsulate(a,"/ip4/192.131.200.111/udp/3333/");
	printf("A STRING ENCAPSULATED:%s\n",a->string);

	multiaddress_decapsulate(a,"udp");
	printf("A STRING DECAPSULATED UDP:%s\n",a->string);

	multiaddress_encapsulate(a,"/tcp/8080");
	printf("A STRING ENCAPSULATED TCP:%s\n",a->string);

	struct MultiAddress* beta;
	beta = multiaddress_new_from_bytes(a->bytes,a->bsize);
	printf("B STRING: %s\n",beta->string);

	multiaddress_free(a);
	multiaddress_free(beta);
	return 1;
}

int test_hex_to_val() {
	return 0;
}

