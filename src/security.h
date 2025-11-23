#ifndef SECURITY_H_
#define SECURITY_H_

#include <stdio.h>

#include "common.h"
#include "peer.h"

void print_salt(char* salt);

void print_signature(char* sig);

void get_signature(char* password, int password_len, char* salt, hashdata_t* hash);

int is_safe_filename(const char* filename);



#endif // SECURITY_H_
