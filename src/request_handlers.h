#ifndef REQUEST_HANDLERS_H_
#define REQUEST_HANDLERS_H_

#include "peer.h"

typedef struct request_thread_args {
    int request_connfd;
} request_thread_args_t;


void handle_register_request(RequestHeader_t* register_header, int connfd);

void handle_inform_request(RequestHeader_t* inform_header, char* inform_body);

void handle_file_request(RequestHeader_t* file_request_header, int connfd, char* file_request_body);

void* handle_server_request(void* arg);

#endif // REQUEST_HANDLERS_H_
