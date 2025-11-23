#ifndef MESSAGES_H_
#define MESSAGES_H_

#include "peer.h"

int handle_response(int clientfd, int request_command, char* request_body, int request_len);

int send_message(NetworkAddress_t peer_address, int command, char* request_body, int request_len);

void send_error_message(char* error_message, int error_code, int connfd);

void send_response(uint32_t connfd, uint32_t status, char* response_body, int response_length);


#endif // MESSAGES_H_
