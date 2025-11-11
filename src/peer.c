#include "common.h"
#include "sha256.h"
/* #include <stdint> */
/* #include <cstddef> */
// #include <cstddef>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/_endian.h>
#include <sys/_pthread/_pthread_mutex_t.h>
#include <sys/_pthread/_pthread_t.h>
#include <sys/_types/_socklen_t.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"


// Global variables to be used by both the server and client side of the peer.
// Note the addition of mutexs to prevent race conditions.
NetworkAddress_t *my_address;

NetworkAddress_t** network = NULL;
uint32_t peer_count = 0;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct request_thread_args {
    int request_connfd;
} request_thread_args_t;

void get_signature(void *password, int password_len, char *salt,
                   hashdata_t* hash) {
  size_t length = strlen(salt) + password_len;
  char password_with_salt[length];
  strcpy(password_with_salt, password);
  strcat(password_with_salt, salt);
  get_data_sha(password_with_salt, hash, length, SHA256_HASH_SIZE);
}

void print_peers(char *data, size_t data_len) {
  int number_of_peers_in_data = data_len / 68;
  for (int i = 0; i < number_of_peers_in_data; i++) {
    int offset = i * 68;
    char first_peer_ip[16];
    memcpy(first_peer_ip, &data[offset], 16);
    uint32_t first_peer_port = ntohl(*(uint32_t *)&data[offset + 16]);
    char first_peer_signature[32];
    memcpy(first_peer_signature, &data[offset + 20], 32);
    char first_peer_salt[16];
    memcpy(first_peer_salt, &data[offset + 52], 16);
    printf("Peer number: %d\n", i);
    printf("IP: %s\n", first_peer_ip);
    printf("Port: %d\n", first_peer_port);
    printf("Signture: %s\n", first_peer_signature);
    printf("Salt: %s\n", first_peer_salt);
    
  }
}

void print_network_address(NetworkAddress_t* address) {
  printf("IP: %s\n", address->ip);
  printf("Port: %d\n", address->port);
  printf("Salt: %s\n", address->salt);
  printf("Signature: %s\n", address->signature);
}  

NetworkAddress_t* make_network_addres_from_response(void *data, int offset) {
  
  NetworkAddress_t* new_peer = malloc(sizeof(NetworkAddress_t));
  char peer_ip[16];
  memcpy(new_peer->ip, &data[offset], 16);
  new_peer->port = ntohl(*(uint32_t *)&data[offset + 16]);
  char peer_signature[32];
  memcpy(new_peer->signature, &data[offset + 20], 32);
  char peer_salt[16];
  memcpy(new_peer->salt, &data[offset + 52], 16);

  return new_peer;
}

int is_in_network(NetworkAddress_t **network, NetworkAddress_t* peer, int number_of_peers) {
  // Checks if the peer is in the network by matching IP and port
  // If it is returns 1, if not returns 0
  for (int i = 0; i < number_of_peers; i++) {
    if ((strcmp(peer->ip, network[i]->ip) == 0) &&
        (peer->port == network[i]->port)) {
      return 1;
    }
  }
  return 0;
  
}

/* void handle_response(int clientfd, int request_command) */

void send_message(NetworkAddress_t peer_address, int command,
                  char *request_body, int request_len) {

  char *peer_ip = peer_address.ip;
  char peer_port[16];
  sprintf(peer_port, "%d", peer_address.port);

  // Create client socket and connect
  int clientfd = compsys_helper_open_clientfd(peer_ip, peer_port);

  // Create and populate request header
  RequestHeader_t *req_head = malloc(sizeof(RequestHeader_t));
  req_head->port = htonl(my_address->port);
  req_head->command = htonl(command);
  memcpy(req_head->ip, my_address->ip, IP_LEN);
  memcpy(req_head->signature, my_address->signature, SHA256_HASH_SIZE);

  // Assemble request header and body
  size_t body_len = strlen(request_body);
  char *send_buffer = malloc(sizeof(RequestHeader_t) + body_len);
  if (send_buffer == NULL) {
    printf("Request buffer failed\n");
  }
  // Putting request header and message body in buffer to be send
  memcpy(send_buffer, req_head, sizeof(RequestHeader_t));
  memcpy(send_buffer + sizeof(RequestHeader_t), request_body, body_len);

  // Send request
  if (compsys_helper_writen(clientfd, req_head, sizeof(RequestHeader_t)) < 1) {
    printf("Error, no bytes send\n");
  }
  // free allocated memory for request header and send buffer
  free(req_head);
  free(send_buffer);

  printf("Message send\n");


  // Handling the response
  // For now this takes care of all three kinds of requests
  // 1 registration, 2 file request, 3 inform message (which doesn't expect response)
  //

  char buf[MAX_MSG_LEN];
  char reply_header[REPLY_HEADER_LEN];
  compsys_helper_state_t state;

  // init clientfd to recieve message from peer
  compsys_helper_readinitb(&state, clientfd);
  size_t n;
  //
  // If bytes being read, enter message parsing
  if ((n = compsys_helper_readnb(&state, reply_header, REPLY_HEADER_LEN)) != 0) {

    uint32_t reply_length = ntohl(*(uint32_t *)&reply_header[0]);

    // check if reply is the right length
    if ((reply_length % 68) != 0) {
      printf("Reply was not a list of peers\n");
    }
    // Check reply code for erros
    uint32_t reply_status = ntohl(*(uint32_t *)&reply_header[4]);
    if (reply_status != 1) {
      printf("Error status code from peer\n");
      switch (reply_status) {
          case 2:
              // Only for peer registration responses
              printf("Peer already exists\n");
              break;
          case 3:
              printf("Peer is missing, hasn't registered yet\n");
              break;
          case 4:
              printf("Password mismatch\n");
              break;
          default:
              break;
              }
    } else {
        // if reply code was 1, continue parsing the header and message
        // parsing reply block header
        uint32_t reply_block_number = ntohl(*(uint32_t *)&reply_header[8]);
        uint32_t reply_block_count = ntohl(*(uint32_t *)&reply_header[12]);
        char reply_block_hash[32];
        memcpy(reply_block_hash, &reply_header[16], 32);
        char reply_block_total_hash[32];
        memcpy(reply_block_total_hash, &reply_header[48], 32);

        // read reply block message
        char message_buf[reply_length];
        size_t nn = compsys_helper_readnb(&state, message_buf, reply_length);

        // check if message hash is identical to hash from header
        char message_hash[32];
        get_data_sha(message_buf, message_hash, reply_length, 32);
        if (memcmp(message_hash, reply_block_hash, 32) != 0) {
          printf("Hashes not identical, something is wrong\n");
        }

        // parse reply message and put new peers in network
        int number_of_peers_in_response = reply_length / 68;
        int previous_peer_count = peer_count;
        //int number_of_new_peers =
        //    abs(number_of_peers_in_response - previous_peer_count);

        int peers_added = 0;
        for (int i = 0; i < number_of_peers_in_response; i++) {
          NetworkAddress_t *peer =
              make_network_addres_from_response(message_buf, i * 68);

          if (is_in_network(network, peer, previous_peer_count) == 0) {
            int next_peer_place_in_network = previous_peer_count + peers_added;
            network[next_peer_place_in_network] = peer;
            peer_count++;
            peers_added++;
          }
        }

        printf("Number of peers in network: %d\n", peer_count);
        for (int i = 0; i < peer_count; i++) {
          print_network_address(network[i]);
        }
        // print_peers(message_buf, reply_length);
    }
    /* } */

    // Close connection
    close(clientfd);
  }
}  

/*
 * Function to act as thread for all required client interactions. This thread
 * will be run concurrently with the server_thread. It will start by requesting
 * the IP and port for another peer to connect to. Once both have been provided
 * the thread will register with that peer and expect a response outlining the
 * complete network. The user will then be prompted to provide a file path to
 * retrieve. This file request will be sent to a random peer on the network.
 * This request/retrieve interaction is then repeated forever.
 */ 
void* client_thread()
{
  char peer_ip[IP_LEN];
  fprintf(stdout, "Enter peer IP to connect to: ");
  scanf("%16s", peer_ip);
  
  // Clean up password string as otherwise some extra chars can sneak in.
  for (int i=strlen(peer_ip); i<IP_LEN; i++)
      {
        peer_ip[i] = '\0';
      }

  char peer_port[PORT_STR_LEN];
  fprintf(stdout, "Enter peer port to connect to: ");
  scanf("%16s", peer_port);
  
  // Clean up password string as otherwise some extra chars can sneak in.
  for (int i=strlen(peer_port); i<PORT_STR_LEN; i++) {
    peer_port[i] = '\0';
    }
  NetworkAddress_t peer_address;
  memcpy(peer_address.ip, peer_ip, IP_LEN);
  peer_address.port = atoi(peer_port);
  
  // Send request message to peer
  send_message(peer_address, 1, "\0", 4);

  while (1) {
    char filename[20];
    fprintf(stdout, "Enter file name to get: ");
    scanf("%s", filename);
    send_message(peer_address, 2, filename, 20);
  }    
  
  // You should never see this printed in your finished implementation
  printf("Client thread done\n");

  return NULL;
}
void send_response(uint32_t connfd, uint32_t status, char* response_body, int response_length) {
    ReplyHeader_t* reply_header = malloc(sizeof(ReplyHeader_t));
    hashdata_t block_hash;
    printf("in send_response\n");
    get_data_sha(response_body, block_hash, response_length, SHA256_HASH_SIZE);
    printf("hash generated\n");
    reply_header->length = htonl(response_length);
    reply_header->block_count = htonl(1);
    reply_header->this_block = htonl(1);
    reply_header->status = htonl(status);
    printf("going to copy hashes\n");
    memcpy(reply_header->block_hash, block_hash, SHA256_HASH_SIZE);
    memcpy(reply_header->total_hash, block_hash, SHA256_HASH_SIZE);

    // Assemble message to be send as response
    size_t total_response_length = sizeof(ReplyHeader_t) + response_length;
    char* outputbuffer = malloc(total_response_length);
    printf("copying things to output buffer\n");
    memcpy(&outputbuffer[0], reply_header, sizeof(ReplyHeader_t));
    printf("copying response to output buffer\n");
    memcpy(&outputbuffer[sizeof(ReplyHeader_t)], response_body, response_length);

    printf("finally writing to network, thank you compsys_helper-elves\n");
    int n = compsys_helper_writen(connfd, outputbuffer, total_response_length);
    printf("%d bytes written and send, total response length is %zu\n", n, total_response_length);


}
/*
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 */
void handle_register_message(RequestHeader_t* register_header, int connfd) {
    printf("%d\n", connfd);
    printf("really close to handling the register message!\n");

    printf("%d and %d", is_valid_ip(register_header->ip), is_valid_port(register_header->port));

    printf("really close to handling the register message again!\n");
    if (is_valid_ip(register_header->ip) && is_valid_port(register_header->port)) {
        printf("Gotten to 295\n");
        // Create new network address for new peer
        NetworkAddress_t* new_peer = malloc(sizeof(NetworkAddress_t));
        new_peer->port = register_header->port;
        printf("Gotten to 299\n");
        memcpy(new_peer->ip, register_header->ip, 16);

        printf("Gotten to 301\n");
        // Generate network saved signature with random salt
        char random_salt[SALT_LEN];
        generate_random_salt(random_salt);
        printf("Gotten to 305\n");
        // Terminate salt string with null-byte.
        // I don't know if it is necessary but handout did it in main
        //random_salt[SALT_LEN] = '\0';
        hashdata_t* network_signature = (hashdata_t*) malloc(sizeof(hashdata_t));

        printf("Gotten to 309\n");
        // Create network signature from register request signature and random salt.
        // Now hardcoded to length 32, as that is what it is, but it probably
        // should use a macro or constant.
        get_signature(register_header->signature, 32, random_salt, network_signature);
        memcpy(new_peer->salt, random_salt, SALT_LEN);
        memcpy(new_peer->signature, network_signature, SHA256_HASH_SIZE);

        printf("Gotten to 317\n");
        // Add to network and increment peer count
        if (!is_in_network(network, new_peer, peer_count)) {
          network[peer_count] = new_peer;
          peer_count++;
        }
        // Print out result
        printf("network updated\n");
        for (int i = 0; i < peer_count; i++) {
            print_network_address(network[i]);
        }
        size_t response_length = 68 * peer_count;
        char* response_body = malloc(response_length);

        // Copy entire network into buffer to send as response
        // Here we're still sending the peer that has just been registered,
        // that it is in the network, but it's probably ok.
        printf("assembling response body\n");
        for (int i = 0; i < peer_count; i++) {
            uint32_t port = htonl(network[i]->port);
            memcpy(&response_body[i*68], &network[i]->ip, 16);
            memcpy(&response_body[i*68+16], &port, 4);
            memcpy(&response_body[i*68+20], network[i]->signature, 32);
            memcpy(&response_body[i*68+52], network[i]->salt, 16);
        }

        // Send the response for register message
        printf("sending response\n");
        send_response(connfd, 1, response_body, response_length);
        close(connfd);

    }
}


void* handle_server_request(void* arg) {
    printf("handling server request\n");
    pthread_detach(pthread_self());
    /* int request_connfd = *((int*) arg); */
    request_thread_args_t* args = (request_thread_args_t*) arg;
    int request_connfd = args->request_connfd;
    printf("connecting with connfd %d", request_connfd);
    free(arg);

    RequestHeader_t* request_header = malloc(sizeof(RequestHeader_t));
    compsys_helper_state_t state;
    char* request_header_buffer = malloc(REQUEST_HEADER_LEN);

    // read request header - TODO implement error handling
    compsys_helper_readinitb(&state, request_connfd);
    compsys_helper_readnb(&state, request_header_buffer, REQUEST_HEADER_LEN);

    // Parse request header
    char request_ip[16];
    memcpy(request_ip, &request_header_buffer[0], 16);

    uint32_t request_port = ntohl(*(uint32_t*)&request_header_buffer[16]);

    char request_signature[32];
    memcpy(request_signature, &request_header_buffer[20], 32);

    uint32_t request_command = ntohl(*(uint32_t*)&request_header_buffer[52]);
    printf("Just parsed request command %d\n", request_command);
    uint32_t request_body_length = ntohl(*(uint32_t*)&request_header_buffer[56]);

    request_header->length = request_body_length;
    request_header->command = request_command;
    printf("Just copied the request command %d into header %d", request_command, request_header->command);
    memcpy(request_header->ip, request_ip, 16);
    request_header->port = request_port;
    memcpy(request_header->signature, request_signature, 32);
    printf("request_command %d\n", request_command);
    if (request_command == 1) {
        printf("Incoming registration request from IP: %s Port: %d\n", request_ip, request_port);
        printf("From header Incoming registration request from IP: %s Port: %d\n", request_header->ip, request_header->port);
        /* if (request_body_length != 0) { */
        /*     printf("body contains message - which it shouldn't\n"); */
        /* } */
        printf("Going to handle register message!\n");
        handle_register_message(request_header, request_connfd);
        // Close the request connection after handling
    } else if (request_command == 2) {
        printf("Incoming file request from IP: %s Port: %d\n", request_ip, request_port);
    } else if (request_command == 3) {
        printf("Incoming inform request from IP: %s Port: %d\n", request_ip, request_port);
        if ((request_body_length % 68) != 0) {
            printf("Request body is the wrong length\n");
                }
    }

    // Read request body - if there is any
    char request_body[request_body_length];
    compsys_helper_readnb(&state, &request_body, request_body_length);

    return NULL;
}
void* server_thread() {
    printf("starting server thread\n");

  int listenfd;
  int connfd;
  char local_port[16];
  int* connfd_ptr = malloc(sizeof(int));
  request_thread_args_t* request_thread_arg = malloc(sizeof(request_thread_args_t));

  // Incoming connection threads
  pthread_t* connection_threads = malloc(sizeof(pthread_t) * 15);

  struct sockaddr_storage clientaddr;
  struct sockaddr_in listen_address;
  int lis_addr_len = sizeof(listen_address);
  sprintf(local_port, "%d", my_address->port);
  listenfd = compsys_helper_open_listenfd(local_port);
  int requests = 0;
  while (1) {
      // Accept incomint connections
      if ((connfd = accept(listenfd, (struct sockaddr*) &clientaddr, (socklen_t*) &lis_addr_len)) < 0) {
          printf("Error in reading incoming connection in server thread\n");
      }
      printf("starting new thread for incoming connection\n");
      /* *connfd_ptr = connfd; */
      request_thread_args_t* arg = malloc(sizeof(request_thread_args_t));
      arg->request_connfd = connfd;
      pthread_create(&connection_threads[requests], NULL, handle_server_request, (void*)arg);
      requests++;
  }
  // You should never see this printed in your finished implementation
  printf("Server thread done\n");

  return NULL;
}


int main(int argc, char **argv)
{
    // Users should call this script with a single argument describing what 
    // config to use
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <IP> <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    my_address = (NetworkAddress_t *)malloc(sizeof(NetworkAddress_t));
    
    memset(my_address->ip, '\0', IP_LEN);
    memcpy(my_address->ip, argv[1], strlen(argv[1]));
    my_address->port = atoi(argv[2]);

    if (!is_valid_ip(my_address->ip)) {
        fprintf(stderr, ">> Invalid peer IP: %s\n", my_address->ip);
        exit(EXIT_FAILURE);
    }
    
    if (!is_valid_port(my_address->port)) {
        fprintf(stderr, ">> Invalid peer port: %d\n", 
            my_address->port);
        exit(EXIT_FAILURE);
    }

    char password[PASSWORD_LEN];
    fprintf(stdout, "Create a password to proceed: ");
    scanf("%16s", password);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(password); i<PASSWORD_LEN; i++)
    {
        password[i] = '\0';
    }

    // Most correctly, we should randomly generate our salts, but this can make
    // repeated testing difficult so feel free to use the hard coded salt below
    char salt[SALT_LEN+1] = "0123456789ABCDEF\0";
    //generate_random_salt(salt);
    memcpy(my_address->salt, salt, SALT_LEN);

    // Create a signature from password and salt, and store in signature    
    hashdata_t *signature = (hashdata_t *)malloc(sizeof(hashdata_t));
    get_signature(password, PASSWORD_LEN, salt, signature);

    // Now hardcoded to 20 but there is probably an elegant way to do it
    network = malloc(sizeof(NetworkAddress_t*) * 50);
    memcpy(my_address->signature, signature, SHA256_HASH_SIZE);
    network[0] = my_address;
    peer_count++;
    
    // Setup the client and server threads 
    pthread_t client_thread_id;
    pthread_t server_thread_id;
    pthread_create(&client_thread_id, NULL, client_thread, NULL);
    pthread_create(&server_thread_id, NULL, server_thread, NULL);

    // Wait for them to complete. 
    pthread_join(client_thread_id, NULL);
    pthread_join(server_thread_id, NULL);

    exit(EXIT_SUCCESS);
}
