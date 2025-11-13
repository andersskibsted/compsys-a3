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
#include <sys/_types/_size_t.h>
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
// Function to shuffle numbers in array
// Used to shuffle order blocks are send in.
// Fisher-Yates shuffle
void shuffle(int *array, int n) {
    for (int i = n - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        // Swap array[i] og array[j]
        int temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }
}

// Helper function to identify problems - probably to be deleted.
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
    // Print network address of as ip:port to stdout
    printf("In network: %s:%d\n", address->ip, address->port);
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

int is_same_peer(NetworkAddress_t* peer1, NetworkAddress_t* peer2) {

    if ((memcmp(peer1->ip, peer2->ip, 16) == 0) && (peer1->port == peer2->port)) {
        return 1;
    } else {
        return 0;
    }
}

NetworkAddress_t* return_random_peer() {
    uint32_t random_peer_number = rand() % peer_count;
    if (is_same_peer(network[random_peer_number], my_address)) {
            random_peer_number = (random_peer_number + 1) % peer_count;
        }
    return network[random_peer_number];
}

void handle_response(int clientfd, int request_command, char* request_body, int request_len) {

  // Handling the response
  // For now this takes care of all three kinds of requests
  // 1 registration, 2 file request, 3 doesn't get a response
  // TODO change reply_header from char array to ReplyHeader_t struct

  char buf[MAX_MSG_LEN];
  char reply_header[REPLY_HEADER_LEN];
  ReplyHeader_t reply_header_struct;
  compsys_helper_state_t state;
  int max_body_length = MAX_MSG_LEN - sizeof(ReplyHeader_t);

  // init clientfd to recieve message from peer
  compsys_helper_readinitb(&state, clientfd);
  size_t n;
  //
  // If bytes being read, enter message parsing
  if ((n = compsys_helper_readnb(&state, reply_header, REPLY_HEADER_LEN)) != 0) {

    uint32_t reply_length = ntohl(*(uint32_t *)&reply_header[0]);
    reply_header_struct.length = reply_length;

    // Check reply code for erros
    uint32_t reply_status = ntohl(*(uint32_t *)&reply_header[4]);
    reply_header_struct.status = reply_status;
    if (reply_status > 3) {
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
        reply_header_struct.this_block = reply_block_number;
        uint32_t reply_block_count = ntohl(*(uint32_t *)&reply_header[12]);
        reply_header_struct.block_count = reply_block_count;
        char reply_block_hash[32];
        memcpy(reply_block_hash, &reply_header[16], 32);
        memcpy(reply_header_struct.block_hash, reply_block_hash, SHA256_HASH_SIZE);
        char reply_block_total_hash[32];
        memcpy(reply_block_total_hash, &reply_header[48], 32);
        memcpy(reply_header_struct.total_hash, reply_block_total_hash, SHA256_HASH_SIZE);

        // if there is only one block in the reply
        if (request_command == 1) {
            // If 1, parse reply message and put new peers in network
            char message_buf[reply_length];
            size_t bytes_received = compsys_helper_readnb(&state, message_buf, reply_length);

            // check if message hash is identical to hash from header
            char message_hash[32];
            get_data_sha(message_buf, message_hash, reply_length, 32);
            if (memcmp(message_hash, reply_block_hash, 32) != 0) {
              printf("Hashes not identical, something is wrong\n");
            }

            int number_of_peers_in_response = reply_length / 68;
            int previous_peer_count = peer_count;

            int peers_added = 0;
            for (int i = 0; i < number_of_peers_in_response; i++) {
              NetworkAddress_t *peer =
                  make_network_addres_from_response(message_buf, i * 68);

              if (is_in_network(network, peer, previous_peer_count) == 0) {
                int next_peer_place_in_network =
                    previous_peer_count + peers_added;
                network[next_peer_place_in_network] = peer;
                peer_count++;
                peers_added++;
              }
            }

            printf("Number of peers in network: %d\n", peer_count);
            for (int i = 0; i < peer_count; i++) {
              print_network_address(network[i]);
            }

            // If 2 write buffer to disk
        } else if (request_command == 2) {
            // Prepare file to be written
            FILE *file;

            // Get filename from request, and terminate with '\0'
            // TODO - why is it + 2 and why request_len + 1?
            char filename[request_len + 2];
            memcpy(filename, request_body, request_len + 1);
            filename[request_len + 1] = '\0';

            // Create file and open it
            file = fopen(filename, "wb");
            if (file == NULL) {
                perror("Error in trying to create file\n");
            }
            printf("Reading first message block body\n");
            // First read message and check hashes
            char message_buf[reply_length];
            size_t bytes_received =
                compsys_helper_readnb(&state, message_buf, reply_length);
            printf("Read %zu bytes, reply length is %d\n", bytes_received, reply_length);
            // check if message hash is identical to hash from header
            char message_hash[32];
            get_data_sha(message_buf, message_hash, reply_length, 32);
            if (memcmp(message_hash, reply_block_hash, 32) != 0) {
                printf("Hashes not identical, something is wrong\n");
            }

            // If just 1 block, write it to file and be done with it
            if (reply_block_count == 1) {
                printf("Only 1 block, writing to file\n");
                fwrite(message_buf, 1, reply_length, file);
                fclose(file);
                close(clientfd);
            } else {
                printf("More than 1 block. There is %d blocks, currently got block %d\n",
                       reply_header_struct.block_count,
                       reply_header_struct.this_block);
                // if more blocks, set up values for book keeping.
                // We already recieved header
                int blocks_recieved = 1;
                int total_blocks = reply_block_count;
                int data_recieved = 0;
                int file_data_recieved = max_body_length;
                int bytes_read = 0;
                // TODO This includes header size, maybe it shouldn't
                int potential_data_to_be_recieved = total_blocks * MAX_MSG_LEN;
                char file_buffer[potential_data_to_be_recieved];
                int current_block = reply_header_struct.this_block;
                // Copy first read message into buffer, so we're ready for
                // the while loop - this might be buggy
                memcpy(&file_buffer[(current_block)*max_body_length], message_buf, max_body_length);
                // loop until all blocks have been recieved
                // TODO - Find a way that first message is READ and stored properly
                // TODO - check hashes in while loop
                // Block numbering is 0 indexed
                while (blocks_recieved < total_blocks) {
                    printf("In while loop, blocks recieved %d out of total %d\n", blocks_recieved, total_blocks);
                    // Read next header
                    ReplyHeader_t* reply_header_while = malloc(sizeof(ReplyHeader_t));
                    char reply_header_buffer[80];
                    int total_read = 0;
                    while (total_read < 80) {
                        bytes_read = compsys_helper_readnb(&state, reply_header_buffer, sizeof(ReplyHeader_t));
                        if (bytes_read <= 0) {
                            printf("Recieving header segment of multi block file failed\n");
                            printf("Read %d bytes\n", bytes_read);
                            break;
                        }
                        total_read += bytes_read;
                    }
                    memcpy(reply_header_while, reply_header_buffer, 80);
                    reply_header_while->length = ntohl(reply_header_while->length);
                    reply_header_while->status = ntohl(reply_header_while->status);
                    reply_header_while->this_block = ntohl(reply_header_while->this_block);
                    reply_header_while->block_count = ntohl(reply_header_while->block_count);
                    //reply_header_while->this_block = ntohl(*(int*)&reply_header_buffer[8]);
                    printf("Read the first header of %d bytes\n", bytes_read);
                    current_block = reply_header_while->this_block;
                    data_recieved += bytes_read;

                    // Read message body for current block
                    int body_length = reply_header_while->length;
                    char message_body_buffer[body_length];
                    printf("Going to read body\n");
                    bytes_read = compsys_helper_readnb(
                        &state, message_body_buffer, body_length);
                    printf("read body\n");
                    if (bytes_read <= 0) {
                      printf("Recieving body segment of multi block file "
                             "failed\n");
                      break;
                    }

                    blocks_recieved++;
                    data_recieved += bytes_read;
                    // To keep track of the final file size
                    // Maybe there is a more robust way
                    file_data_recieved += bytes_read;
                    printf("Copying to file buffer, body length is %d vs max_body_length %d\n",
                           body_length, max_body_length);
                    // Copy to message buffer to file buffer
                    memcpy(&file_buffer[(current_block) * max_body_length],
                           message_body_buffer, body_length);
                    printf("Done copying, ready for another round\n");
                    free(reply_header_while);

                }
                printf("Out of while loop, blocks recieved %d and data recieved %d\n", blocks_recieved, file_data_recieved);
                // Write file buffer to file
                fwrite(file_buffer, 1, file_data_recieved, file);
                fclose(file);
                close(clientfd);
                // Free memory
                // TODO
            }
        }
    }
  }
}

void send_message(NetworkAddress_t peer_address, int command,
                  char *request_body, int request_len) {

  char *peer_ip = peer_address.ip;
  char peer_port[16];
  sprintf(peer_port, "%d", peer_address.port);
  if (command == 3) {
      int request_body_port;
      memcpy(&request_body_port, &request_body[16], 4);
      printf("Informing %d of new peer on port %d", peer_address.port, ntohl(request_body_port));
  }

  // Create client socket and connect
  int clientfd = compsys_helper_open_clientfd(peer_ip, peer_port);

  // Create and populate request header
  RequestHeader_t *req_head = malloc(sizeof(RequestHeader_t));
  req_head->port = htonl(my_address->port);
  req_head->command = htonl(command);
  if (command != 1) {
      req_head->length = htonl(request_len);
  }
  memcpy(req_head->ip, my_address->ip, IP_LEN);
  memcpy(req_head->signature, my_address->signature, SHA256_HASH_SIZE);

  // Assemble request header and body
  //size_t body_len = strlen(request_body);
  char *send_buffer = malloc(sizeof(RequestHeader_t) + request_len);
  if (send_buffer == NULL) {
    printf("Request buffer failed\n");
  }
  // Putting request header and message body in buffer to be send
  memcpy(&send_buffer[0], req_head, sizeof(RequestHeader_t));
  memcpy(&send_buffer[sizeof(RequestHeader_t)], request_body, request_len);

  size_t total_message_length = request_len + sizeof(RequestHeader_t);
  // Send request
  printf("Sending command %d\n", command);

  if (compsys_helper_writen(clientfd, send_buffer, total_message_length) < 1) {
    printf("Error, no bytes send for inform or file request\n");
  }

  // free allocated memory for request header and send buffer
  free(req_head);
  free(send_buffer);

  printf("Message send\n");
  // Handle response if relevant
  if (command != 3) {
      handle_response(clientfd, command, request_body, request_len);
  }
  // close connection after response has been handled
  close(clientfd);

}

void send_error_message(char* error_message, int error_code, int connfd) {
    char* message_buffer = malloc(100);
    int message_length = 0;
    switch (error_code) {
        case 2:
            printf("Peer already exists\n");
            char* message_buffer2 = "Cannot register, peer already exists.\0";
            message_length = strlen(message_buffer2);
            memcpy(message_buffer, message_buffer2, message_length);
            break;
        case 3:
            printf("Peer trying to request file is not registered in network\n");
            char* message_buffer3 = "Cannot fullfil request, peer not registered in network\0";
            message_length = strlen(message_buffer3);
            memcpy(message_buffer, message_buffer3, message_length);
            break;
        case 4:
            printf("Password mismatch\n");
            char* message_buffer4 = "Password mismatch\0";
            message_length = strlen(message_buffer4);
            memcpy(message_buffer, message_buffer4, message_length);
            break;
        case 5:
            printf("Bad request. Cannot be fullfilled right now.\n");
            char* message_buffer5 = "Bad request. Cannot be fullfilled right now.\0";
            message_length = strlen(message_buffer);
            memcpy(message_buffer, message_buffer5, message_length);
            break;
        case 6:
            printf("Other unknown error.\n");
            char* message_buffer6 = "Other unknown error.\0";
            message_length = strlen(message_buffer6);
            memcpy(message_buffer, message_buffer6, message_length);
            break;
        case 7:
            printf("Malformed request. Cannot be processed.\n");
            char* message_buffer7 = "Malformed request.\0";
            message_length = strlen(message_buffer7);
            memcpy(message_buffer, message_buffer7, message_length);
            break;
        default:
            break;
    }
    ReplyHeader_t* reply_header = malloc(sizeof(ReplyHeader_t));
    reply_header->length = htonl(message_length);
    reply_header->status = htonl(error_code);
    reply_header->this_block = htonl(1);
    reply_header->block_count = htonl(1);
    hashdata_t block_hash;
    char random_salt[SALT_LEN];
    generate_random_salt(random_salt);
    get_data_sha(message_buffer, block_hash, message_length, SHA256_HASH_SIZE);
    memcpy(reply_header->block_hash, block_hash, SHA256_HASH_SIZE);
    memcpy(reply_header->total_hash, block_hash, SHA256_HASH_SIZE);
    // TODO - simplify. Structs are just bytes, so they can be copied
    // directly
    char outputbuffer[sizeof(ReplyHeader_t) + message_length];
    memcpy(&outputbuffer[0], &reply_header->length, 4);
    memcpy(&outputbuffer[4], &reply_header->status, 4);
    memcpy(&outputbuffer[8], &reply_header->this_block, 4);
    memcpy(&outputbuffer[12], &reply_header->block_count, 4);
    memcpy(&outputbuffer[16], &reply_header->block_hash, 32);
    memcpy(&outputbuffer[48], &reply_header->total_hash, 32);
    memcpy(&outputbuffer[80], message_buffer, message_length);
    compsys_helper_writen(connfd, message_buffer, message_length);
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
  NetworkAddress_t* peer_address = malloc(sizeof(NetworkAddress_t));
  memcpy(peer_address->ip, peer_ip, IP_LEN);
  peer_address->port = atoi(peer_port);

  // Update network with peer we are requesting connection to
  pthread_mutex_lock(&lock);
  network[peer_count] = peer_address;
  peer_count++;
  pthread_mutex_unlock(&lock);
  // Send registration request message to peer
  send_message(*peer_address, 1, "", 0);



  while (1) {
    char filename_buffer[255];
    int chars_read = 0;
    fprintf(stdout, "Enter file name to get: ");
    scanf("%s%n", filename_buffer, &chars_read);
    NetworkAddress_t* random_peer = return_random_peer();
    char filename[chars_read];
    memcpy(filename, filename_buffer, chars_read);
    printf("%s\n", filename);
    send_message(*random_peer, 2, filename, chars_read-1);
  }    
  
  // You should never see this printed in your finished implementation
  printf("Client thread done\n");

  return NULL;
}


void send_response(uint32_t connfd, uint32_t status, char* response_body, int response_length) {

    int max_body_length = MAX_MSG_LEN - (sizeof(ReplyHeader_t));
    int number_of_blocks = 0;
    int size_of_last_block = 0;
    //int* random_order;
    char* block_buffer;

    ReplyHeader_t* reply_header = malloc(sizeof(ReplyHeader_t));
    hashdata_t total_hash;


    // Common header attributes no matter the length of the data being sent
    // total hash
    get_data_sha(response_body, total_hash, response_length, SHA256_HASH_SIZE);
    memcpy(reply_header->total_hash, total_hash, SHA256_HASH_SIZE);


    if (response_length < max_body_length) {
        // if data can fit into one block
        reply_header->length = htonl(response_length);
        reply_header->block_count = htonl(1);
        // TODO - might bug, changed from 0 to 1
        reply_header->this_block = htonl(0);
        reply_header->status = htonl(status);

        memcpy(reply_header->block_hash, total_hash, SHA256_HASH_SIZE);

        // Assemble message to be send as response
        size_t total_response_length = sizeof(ReplyHeader_t) + response_length;
        char *outputbuffer = malloc(total_response_length);

        memcpy(&outputbuffer[0], reply_header, sizeof(ReplyHeader_t));
        memcpy(&outputbuffer[sizeof(ReplyHeader_t)], response_body,
               response_length);

        int n =
            compsys_helper_writen(connfd, outputbuffer, total_response_length);
        printf("%d bytes written and send, total response length is %zu\n", n,
               total_response_length);
        // Free output buffer - TODO check if this is to early and
        // causes memory problems for compsys_writen - it shouldn't!
        free(outputbuffer);

    } else {
        printf("sending file over multiple blocks\n");
        // If message size is bigger than what fits in one block
        // Calculate number of blocks and last block size
        number_of_blocks = (response_length/max_body_length) + 1;
        size_of_last_block = response_length%max_body_length;
        printf("number of blocks %d and size of last %d\n", number_of_blocks, size_of_last_block);

        // Allocate memory for all blocks in a buffer.
        // TODO maybe it's too verbose to account for the last block size...
        // Just allocate a bit extra.
        // TODO - check for errors in allocation
        block_buffer = malloc((number_of_blocks) * MAX_MSG_LEN); //+ size_of_last_block + sizeof(ReplyHeader_t));
        // Block count og length for all but last block in header - host to network byte order!
        reply_header->block_count = htonl(number_of_blocks);
        reply_header->length = htonl(max_body_length);

        // Assemble all but last blocks and put them in block_buffer
        for (int i = 0; i<(number_of_blocks - 1); i++) {
            printf("assembling blocks, i is %d, in htonl it's %d\n", i, htonl(i));
            reply_header->this_block = htonl(i);
            printf("this block %d\n", reply_header->this_block);

            // Create buffer for this specific blocks data and
            // copy from response_body
            char block_data[max_body_length];
            memcpy(block_data, &response_body[i*max_body_length], max_body_length);

            // Allocate and create block hash to be put in this specific header
            hashdata_t block_hash;
            get_data_sha(block_data, block_hash, max_body_length, SHA256_HASH_SIZE);
            memcpy(reply_header->block_hash, block_hash, SHA256_HASH_SIZE);

            // Copy this block (reply_header + block_data) to the block_buffer. It should be ok,
            // since data is copied, and when these pointers go out of scope
            // data is copied, not just referenced.
            /* memcpy(&block_buffer[i*MAX_MSG_LEN], &reply_header->length, 4); */
            /* memcpy(&block_buffer[i*MAX_MSG_LEN + 4], &reply_header->status, 4); */
            /* memcpy(&block_buffer[i*MAX_MSG_LEN + 8], &reply_header->this_block, 4); */
            /* memcpy(&block_buffer[i*MAX_MSG_LEN + 12], &reply_header->block_count, 4); */
            /* memcpy(&block_buffer[i*MAX_MSG_LEN + 16], &reply_header->block_hash, 32); */
            /* memcpy(&block_buffer[i*MAX_MSG_LEN + 48], &reply_header->total_hash, 32); */


            memcpy(&block_buffer[i*MAX_MSG_LEN], reply_header, sizeof(ReplyHeader_t));
            memcpy(&block_buffer[i*MAX_MSG_LEN + sizeof(ReplyHeader_t)], block_data, max_body_length);
        }
        // Create the last smaller block.
        // Create block data - copy from response_body, at the position for loop left of
        // That was next to last block, and this is the last block of max_body_length data chunks
        // TODO - potential bug here! I think it should be -1, since it is zero indexed,
        //size_of_last_block=MAX_MSG_LEN;
        char block_data[size_of_last_block];
        memcpy(block_data, &response_body[(number_of_blocks-1)*max_body_length], size_of_last_block);
        // Create block hash for last smaller block
        hashdata_t block_hash;
        get_data_sha(block_data, block_hash, size_of_last_block, SHA256_HASH_SIZE);
        // Populate reply header - block_count is duplicate : already done
        // length of smaller data chunk, this block count and total count
        // is the same.
        // Total hash already set.
        memcpy(reply_header->block_hash, block_hash, SHA256_HASH_SIZE);
        reply_header->length = htonl(size_of_last_block);
        reply_header->this_block = htonl(number_of_blocks-1);
        reply_header->block_count = htonl(number_of_blocks);
        // copy into block buffer
        memcpy(&block_buffer[(number_of_blocks-1)*MAX_MSG_LEN], reply_header, sizeof(ReplyHeader_t));
        memcpy(&block_buffer[(number_of_blocks-1)*MAX_MSG_LEN + sizeof(ReplyHeader_t)], block_data, size_of_last_block);

        // Random order for sending blocks
        // seed random generator
        srand(time(NULL));
        //random_order = malloc(sizeof(int) * number_of_blocks);
        int random_order[number_of_blocks];
        for (int i = 0; i<number_of_blocks; i++) {
            random_order[i] = i;
        }
        shuffle(random_order, number_of_blocks);

        for (int block = 0; block < number_of_blocks; block++) {
            int random_block = random_order[block];
            char send_buffer[MAX_MSG_LEN];
            if (random_block < (number_of_blocks-1)) {
                // If not last block, send the MAX_MSG_LEN
                // TODO - could be much less verbose
                printf("Sending block %d / %d\n", random_block, number_of_blocks);
                ReplyHeader_t current_header;
                //memcpy(&current_header, &block_buffer[random_block*MAX_MSG_LEN], 80);
                //printf("Block number from header is %d\n", ntohl(current_header.this_block));

                memcpy(send_buffer, &block_buffer[random_block * MAX_MSG_LEN],
                       MAX_MSG_LEN);
                memcpy(&current_header, send_buffer, 80);
                printf("Block number from header in send_buffer is %d\n", ntohl(current_header.this_block));
                /* printf("From send buffer %d\n") */
                int n = compsys_helper_writen(connfd, send_buffer, MAX_MSG_LEN);
                //memcpy(&current_header, send_buffer, 80);
                //printf("Block number from header in send_buffer after sending is %d\n", ntohl(current_header.this_block));
                printf("%d bytes written and send, total response length is %d\n",
                       n, MAX_MSG_LEN);
            } else {

                printf("Sending block %d / %d\n", random_block, number_of_blocks);
                // If last block, shorter length
                memcpy(send_buffer, &block_buffer[random_block * MAX_MSG_LEN],
                       size_of_last_block+sizeof(ReplyHeader_t));
                int n = compsys_helper_writen(connfd, send_buffer, size_of_last_block+sizeof(ReplyHeader_t));
                printf("%d bytes written and send for last block, total length is %d\n",
                       n, size_of_last_block);
            }
        }

    }

    // Free reply_header - TODO check if this is to early and
    // causes memory problems for compsys_writen - it shouldn't!
    free(reply_header);
    free(block_buffer);
}
void handle_inform_message(RequestHeader_t* inform_header, char* inform_body) {
    // inform_body must be 68 bytes!!
    // Check if message is from valid source
    if (is_valid_ip(inform_header->ip) && is_valid_port(inform_header->port)) {
        // Create new network address for network array
        NetworkAddress_t* new_peer = malloc(sizeof(NetworkAddress_t));
        memcpy(new_peer->ip, &inform_body[0], 16);

        uint32_t port_network_order;
        memcpy(&port_network_order, &inform_body[16], 4);
        new_peer->port = ntohl(port_network_order);
        /* new_peer->port = ntohl(inform_body[16]); */
        // TODO - I don't know if this signature should be salted and hashed again?
        /* hashdata_t* new_peer_network_sig = (hashdata_t*) malloc(sizeof(hashdata_t)); */
        /* char random_salt[SALT_LEN]; */
        /* generate_random_salt(random_salt); */
        /* get_signature(inform_body, 32, random_salt, new_peer_network_sig); */
        memcpy(new_peer->signature, &inform_body[20], 32);
        memcpy(new_peer->salt, &inform_body[52], 16);
        network[peer_count] = new_peer;
        peer_count++;

        printf("Updating network on inform. Number of peers %d\n", peer_count);
        for (int n = 0; n<peer_count; n++) {
            print_network_address(network[n]);
        }

    }
}
/*
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 */
void handle_register_message(RequestHeader_t* register_header, int connfd) {

    if (is_valid_ip(register_header->ip) && is_valid_port(register_header->port)) {
        // Create new network address for new peer
        NetworkAddress_t* new_peer = malloc(sizeof(NetworkAddress_t));
        new_peer->port = register_header->port;
        memcpy(new_peer->ip, register_header->ip, 16);

        // Generate network saved signature with random salt
        char random_salt[SALT_LEN];
        generate_random_salt(random_salt);
        // Terminate salt string with null-byte.
        // I don't know if it is necessary but handout did it in main
        //random_salt[SALT_LEN] = '\0';
        hashdata_t* network_signature = (hashdata_t*) malloc(sizeof(hashdata_t));

        // Create network signature from register request signature and random salt.
        // Now hardcoded to length 32, as that is what it is, but it probably
        // should use a macro or constant.
        get_signature(register_header->signature, 32, random_salt, network_signature);
        memcpy(new_peer->salt, random_salt, SALT_LEN);
        memcpy(new_peer->signature, network_signature, SHA256_HASH_SIZE);

        // Add to network and increment peer count
        if (!is_in_network(network, new_peer, peer_count)) {
            pthread_mutex_lock(&lock);
            network[peer_count] = new_peer;
            peer_count++;
            pthread_mutex_unlock(&lock);
        }
        // Print out result
        printf("network updated after register message\n");
        for (int i = 0; i < peer_count; i++) {
            print_network_address(network[i]);
        }
        size_t response_length = 68 * peer_count;
        char* response_body = malloc(response_length);

        // Copy entire network into buffer to send as response
        // Here we're still sending the peer that has just been registered,
        // that it is in the network, but it's probably ok.
        for (int i = 0; i < peer_count; i++) {
            uint32_t port = htonl(network[i]->port);
            memcpy(&response_body[i*68], &network[i]->ip, 16);
            memcpy(&response_body[i*68+16], &port, 4);
            memcpy(&response_body[i*68+20], network[i]->signature, 32);
            memcpy(&response_body[i*68+52], network[i]->salt, 16);
        }

        // Send the response for register message
        send_response(connfd, 1, response_body, response_length);
        close(connfd);

        // Send inform messages to rest of network
        for (int peer = 0; peer < peer_count; peer++) {
            if (!is_same_peer(network[peer], new_peer) && !is_same_peer(network[peer], my_address)) {
              // do not send inform message to newly registered peer
              // TODO - Needs more robust handling, as this is just because
              // newly registered peer is the last in the network array

              // Allocate memory for inform message
              /* RequestHeader_t* inform_header =
               * malloc(sizeof(RequestHeader_t)); */
              char *inform_body = malloc(68);
              /* char message_buffer[68 + sizeof(RequestHeader_t)]; */

              // Assemble inform request header
              /* memcpy(inform_header->ip, my_address->ip, 16); */
              /* inform_header->port = htonl(my_address->port); */
              /* memcpy(inform_header->signature, my_address->signature,
               * SHA256_HASH_SIZE); */
              /* inform_header->command = htonl(3); */
              /* inform_header->length = htonl(68); */

              // Assemble body with info on new peer in network
              uint32_t new_peer_port = htonl(new_peer->port);
              memcpy(&inform_body[0], new_peer->ip, 16);
              memcpy(&inform_body[16], &new_peer_port, 4);
              memcpy(&inform_body[20], new_peer->signature, 32);
              memcpy(&inform_body[52], new_peer->salt, 16);

              // Assemble total inform message
              /* memcpy(&message_buffer[0], inform_body,
               * sizeof(RequestHeader_t)); */
              /* memcpy(&message_buffer[sizeof(RequestHeader_t)], response_body,
               * 68); */
              print_network_address(network[peer]);
              send_message(*network[peer], 3, inform_body, 68);
            }
        }

        // Free new_peer memory - TODO check if this is okay, or if code
        // advances and gets into trouble because new_peer is gone, while
        // send_message is accessing it
        //free(new_peer);
    }
}

void handle_file_request(RequestHeader_t* file_request_header, int connfd, char* file_request_body) {

    int body_length = file_request_header->length;
    char filename[body_length+1];
    FILE *file;
    char* buffer;
    uint32_t file_size;
    size_t bytes_read;
    ReplyHeader_t* reply_header;
    hashdata_t block_hash;

    memcpy(filename, file_request_body, body_length);
    filename[body_length] = '\0';

    printf("trying to open:\n");
    printf("%s\n", filename);
    // Open requested file
    file = fopen(filename, "r");
    if (file == NULL) {
        perror("Could not open requested file\n");
    }

    // Find file size
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    rewind(file);

    // Allocate buffer for file content
    buffer = (char*) malloc(file_size + 1);
    // Check for error in allocation
    if (buffer == NULL) {
        perror("Error in allocation of buffer for file content\n");
        fclose(file);
    }

    // Read file into buffer
    bytes_read = fread(buffer, 1, file_size, file);
    buffer[bytes_read] = '\0';


    memcpy(filename, file_request_body, body_length);
    printf("%s\n", filename);

    fclose(file);

    // Allocate and assemble reply header - maybe not as send_response does it
    // TODO - potential bug... I don't  know the right way to initialize hashdata_t
    // TODO - This is still only for one block file sizes
    /* reply_header = (ReplyHeader_t*)malloc(sizeof(ReplyHeader_t)); */
    /* get_data_sha(buffer, block_hash, file_size+1, SHA256_HASH_SIZE); */


    /* reply_header->length = htonl(file_size); */
    /* // Status code OK! */
    /* reply_header->status = htonl(1); */
    /* reply_header->this_block = htonl(1); */
    /* reply_header->block_count = htonl(1); */
    /* memcpy(reply_header->block_hash, block_hash, SHA256_HASH_SIZE); */
    /* memcpy(reply_header->total_hash, block_hash, SHA256_HASH_SIZE); */

    // Calculate number of needed blocks
    // !! MAX_MSG_LEN includes header, so data is only MAX_MSG_LEN - sizeof(ReplyHeader)

    printf("Sending file as response to request. bytes_read %zu is and file size is %d", bytes_read, file_size);
    send_response(connfd, 1, buffer, bytes_read);




}

void* handle_server_request(void* arg) {
    pthread_detach(pthread_self());
    /* int request_connfd = *((int*) arg); */
    request_thread_args_t* args = (request_thread_args_t*) arg;
    int request_connfd = args->request_connfd;
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
    uint32_t request_body_length = ntohl(*(uint32_t*)&request_header_buffer[56]);

    request_header->length = request_body_length;
    request_header->command = request_command;
    memcpy(request_header->ip, request_ip, 16);
    request_header->port = request_port;
    memcpy(request_header->signature, request_signature, 32);

    // Read request body - if there is any
    char request_body[request_body_length];
    compsys_helper_readnb(&state, &request_body, request_body_length);
    printf("handling server request with command: %d\n", request_command);

    // Handle request based on request command
    if (request_command == 1) {
        printf("Incoming registration request from IP: %s Port: %d\n", request_ip, request_port);
        if (request_body_length != 0) {
            printf("body contains message - which it shouldn't\n");
        }
        handle_register_message(request_header, request_connfd);

    } else if (request_command == 2) {
        printf("Incoming file request from IP: %s Port: %d\n", request_ip, request_port);
        handle_file_request(request_header, request_connfd, request_body);

    } else if (request_command == 3) {
        printf("Incoming inform request from IP: %s Port: %d\n", request_ip, request_port);

        handle_inform_message(request_header, request_body);
        if ((request_body_length % 68) != 0) {
            printf("Inform request body is the wrong length. It is: %d\n", request_body_length);
            send_error_message("", 7, request_connfd);
        }
    }


    return NULL;
}
void* server_thread() {

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
      printf("Starting new thread for incoming connection\n");
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

    // Now hardcoded to 50 but there is probably an elegant way to do it
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
