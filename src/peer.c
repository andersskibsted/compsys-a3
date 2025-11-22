#include "common.h"
#include "sha256.h"
#include <ctype.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/_endian.h>
#include <sys/_pthread/_pthread_attr_t.h>
#include <sys/_pthread/_pthread_cond_t.h>
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
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

int not_alone = 0;
int active_threads = 0;
int is_registered = 0;

typedef struct request_thread_args {
    int request_connfd;
} request_thread_args_t;

int is_safe_filename (const char* filename) {
    // Check for safe filenames.
    // Returns 1 if safe, 0 if not.
    size_t max_length = 50;
    size_t length = strlen(filename);
    const char allowed_special_characters[] = {
    '.', '-', '_', '\0'};
    const char* dangerous_file_substrings[] = {
    ".exe", ".EXE", ".bat", ".BAT", ".sh", ".SH",
    "..", NULL
};

    // Check for null filename
    if (!filename || length == 0) {
        return 0;
    }
    // Check length
    if (length > max_length) {
        return 0;
    }
    // Hidden files/dot-files
    if (filename[0] == '.') {
        return 0;
    }

    for (size_t i = 0; i<length; i++) {
        // Check if only allowed characters are used.
        char c = filename[i];
        int is_valid = isalnum(c);
        for (int j = 0; allowed_special_characters[j] != '\0'; j++){
            is_valid = is_valid || allowed_special_characters[j] == c;
        }

        if (!is_valid) {
            printf("Char %c unsafe\n", c);
            return 0;
        }
    }

    for (size_t i = 0; dangerous_file_substrings[i] != NULL; i++) {
        // Check if any of the dangerous extensions is embedded in filename,
        // indicating malicious file.
        if (strstr(filename, dangerous_file_substrings[i]) != NULL) {
            return 0;
        }
    }

    // Safe
    return 1;
}

void print_salt(char* salt) {
     printf("Printing - Salt: ");
        for (int i = 0; i < 16; i++) printf("%c", (char)salt[i]);
    printf("\n");
}
void print_signature(char* sig) {
     printf("Printing - Signature: ");
        for (int i = 0; i < SHA256_HASH_SIZE; i++) printf("%02x", (unsigned char)sig[i]);
    printf("\n");
}

void get_signature(char *password, int password_len, char *salt, hashdata_t* hash) {
  size_t length = SALT_LEN + password_len;
  char password_with_salt[length];
  memcpy(password_with_salt, password, password_len);
  memcpy(&password_with_salt[password_len], salt, SALT_LEN);
  get_data_sha(password_with_salt, *hash, length, SHA256_HASH_SIZE);
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

  }
}

void print_network_address(NetworkAddress_t* address) {
    // Print network address of as ip:port to stdout
    printf("In network: %s:%d\n", address->ip, address->port);
}

void make_network_addres_from_response(void *data, NetworkAddress_t* new_peer, int offset) {
  // Parse data read in from response to a register request.
  // offset is because it is used in a loop, so it reads from entire message
  // body, and only reads info of one peer

  memcpy(new_peer->ip, &data[offset], 16);
  new_peer->port = ntohl(*(uint32_t *)&data[offset + 16]);
  memcpy(new_peer->signature, &data[offset + 20], 32);
  memcpy(new_peer->salt, &data[offset + 52], 16);

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
    // Checks if the two network address have matching ip and port.
    // If so returns 1, if not returns 0
    if ((memcmp(peer1->ip, peer2->ip, 16) == 0) && (peer1->port == peer2->port)) {
        return 1;
    } else {
        return 0;
    }
}

int find_in_network(NetworkAddress_t* peer_to_match, NetworkAddress_t* new_peer_location) {
    // Looks up and finds peer in network returning network address
    // with signature and salt.
    // returns 1 if found, 0 if not.
    int exit_status = 0;
    if (is_in_network(network, peer_to_match, peer_count)) {
        for (int i = 0; i<peer_count; i++) {
            if (is_same_peer(peer_to_match, network[i])) {
                memcpy(new_peer_location, network[i], sizeof(NetworkAddress_t));
                exit_status = 1;
            }
        }
    }
    // return status 0.
    return exit_status;
}


int is_same_ip_and_port(char* ip1, int port1, char* ip2, int port2) {
    // Checks if the two inputs have matching ip and port.
    // If so returns 1, if not returns 0
    if (is_valid_ip(ip1) && is_valid_ip(ip2) && is_valid_port(port1) && is_valid_port(port2)) {
        return ((memcmp(ip1, ip2, 16) == 0) && (port1 == port2));
    } else {
        printf("Not valid ip or port to match\n");
        return 0;
    }
    return 0;
}


NetworkAddress_t* return_random_peer() {
    // Returns a random peer from the network array of stored peers.
    // Does not return it self
    uint32_t random_peer_number = rand() % peer_count;
    if (is_same_peer(network[random_peer_number], my_address)) {
            random_peer_number = (random_peer_number + 1) % peer_count;
        }
    return network[random_peer_number];
}

int handle_response(int clientfd, int request_command, char* request_body, int request_len) {

  // Handling the response
  // This takes care of all three kinds of requests
  // 1 registration, 2 file request, 3 doesn't get a response
  // For 2 it needs original request message and length to get filename for file to be
  // recieved.

  char buf[MAX_MSG_LEN];
  char reply_header[REPLY_HEADER_LEN];
  compsys_helper_state_t state;
  int max_body_length = MAX_MSG_LEN - sizeof(ReplyHeader_t);

  compsys_helper_readinitb(&state, clientfd);
  size_t n = 0;

  // If bytes being read, enter message parsing
  size_t bytes_read = 0;
  while (bytes_read < REPLY_HEADER_LEN) {

      if ((n = compsys_helper_readnb(&state, reply_header, REPLY_HEADER_LEN)) < 0) {
        printf("Error while recieving response.\n");
        return -1;
      }
      bytes_read += n;
  }

  printf("Read %zu bytes of response\n", n);
  uint32_t reply_length = ntohl(*(uint32_t *)&reply_header[0]);

  // Check reply code for erros
  uint32_t reply_status = ntohl(*(uint32_t *)&reply_header[4]);
  printf("Reply status %d\n", reply_status);

  // Reply status contains errors
  if (reply_status > 1) {
    printf("Error status code from peer %d\n", reply_status);
    switch (reply_status) {
    case 2:
      // Only for peer registration responses
      printf("Peer already exists\n");
      break;
    case 3:
      printf("Peer is missing in network we requested from, hasn't registered "
             "yet\n");
      break;
    case 4:
      printf("Password mismatch\n");
      break;
    case 5:
      printf("Peer to busy to handle request or file didn't exist, trying "
             "again\n");
      return 0;
      break;
    case 6:
      printf("Unknow error occured at peer.\n");
      break;
    case 7:
      printf("Request was malformed, please try again.\n");
    default:
      break;
    }
  } else {
    // if reply code was 1, continue parsing the header and message

    // Parsing reply block header into variables and then into fields
    uint32_t reply_block_number = ntohl(*(uint32_t *)&reply_header[8]);
    uint32_t reply_block_count = ntohl(*(uint32_t *)&reply_header[12]);
    char reply_block_hash[32];
    memcpy(reply_block_hash, &reply_header[16], 32);
    char reply_block_total_hash[32];
    memcpy(reply_block_total_hash, &reply_header[48], 32);

    if (request_command == 1) {
      // If 1, original request was registration,
      // read and parse reply message and put new peers in network
      char message_buf[reply_length];
      size_t bytes_received =
          compsys_helper_readnb(&state, message_buf, reply_length);

      // check if message hash is identical to hash from header
      char message_hash[32];
      get_data_sha(message_buf, message_hash, reply_length, 32);
      if (memcmp(message_hash, reply_block_hash, 32) != 0) {

        printf("Hash of data not identical to header hash.\n");
        printf("Data might be corrupted, please try registering again.\n");
        close(clientfd);
        return -1;
      }

      int number_of_peers_in_response = reply_length / 68;
      int previous_peer_count = peer_count;

      int peers_added = 0;

      pthread_mutex_lock(&lock);

      for (int i = 0; i < number_of_peers_in_response; i++) {
        NetworkAddress_t *peer = malloc(sizeof(NetworkAddress_t));
        make_network_addres_from_response(message_buf, peer, i * 68);

        if (!is_in_network(network, peer, previous_peer_count)) {
          NetworkAddress_t **new_network =
              realloc(network, sizeof(NetworkAddress_t *) * (peer_count + 1));
          if (new_network == NULL) {
            printf("Memory allocation error.\n");
          } else {
            network = new_network;
          }

          int next_peer_place_in_network = previous_peer_count + peers_added;
          network[next_peer_place_in_network] = peer;
          peer_count++;
          peers_added++;
        }
        not_alone = 1;
      }
      is_registered = 1;
      printf("Number of peers in network: %d\n", peer_count);
      for (int i = 0; i < peer_count; i++) {
        print_network_address(network[i]);
      }
      // Broadcast to all waiting inform request threads
      // that registration is done, and they are allowed to work.
      pthread_cond_broadcast(&cond);
      pthread_mutex_unlock(&lock);

      // If 2, it is a file request response
      // write buffer to disk
    } else if (request_command == 2) {

      // Prepare file to be written
      FILE *file;

      // Get filename from request message, and terminate with '\0'
      char filename[request_len + 1];
      memcpy(filename, request_body, request_len);
      filename[request_len] = '\0';

      // Create file and open it
      file = fopen(filename, "wb");
      if (file == NULL) {
        perror("Error in trying to create file.\n");
        close(clientfd);
        return -1;
      }

      // First read message and check hashes
      char message_buf[reply_length];
      size_t bytes_received =
          compsys_helper_readnb(&state, message_buf, reply_length);

      // check if message hash is identical to hash from header
      char message_hash[32];
      get_data_sha(message_buf, message_hash, reply_length, 32);
      if (memcmp(message_hash, reply_block_hash, 32) != 0) {
        printf("Hashes not identical, something is wrong\n");
        close(clientfd);
        return -1;
      }

      // If just 1 block, write it to all to file
      if (reply_block_count == 1) {
        size_t bytes_written = fwrite(message_buf, 1, reply_length, file);
        if (bytes_written != reply_length) {
          printf("Error writing incoming file to disk.\n");
          fclose(file);
          close(clientfd);
          return -1;
        }
        fclose(file);
        close(clientfd);
      } else {
        // if more blocks, set up values for book keeping.
        // We already recieved response header in the beginning.
        int blocks_recieved = 1;
        int total_blocks = reply_block_count;
        int file_data_recieved = max_body_length;
        int bytes_read = 0;

        int potential_data_to_be_recieved = total_blocks * MAX_MSG_LEN;
        char file_buffer[potential_data_to_be_recieved];
        int current_block = reply_block_number;

        // Copy first read message into buffer, so we're ready for
        // the while loop
        memcpy(&file_buffer[(current_block)*max_body_length], message_buf,
               max_body_length);
        // loop until all blocks have been recieved
        // Block numbering is 0 indexed
        while (blocks_recieved < total_blocks) {

          // Read next header
          // ReplyHeader_t* reply_header_while = malloc(sizeof(ReplyHeader_t));
          char reply_header_buffer[80];
          int total_read = 0;
          // This is the way it's done in robust_server.c from lecture code
          while (total_read < 80) {
            bytes_read = compsys_helper_readnb(&state, reply_header_buffer,
                                               sizeof(ReplyHeader_t));
            if (bytes_read <= 0) {
              printf("Receiving header segment of multi block file failed\n");
              printf("Read %d bytes\n", bytes_read);
              break;
            }
            total_read += bytes_read;
          }
          // Parsing reply block header into variables
          uint32_t body_length = ntohl(*(uint32_t *)&reply_header_buffer[0]);
          // uint32_t status = ntohl(*(uint32_t*)&reply_header_buffer[4]);
          current_block = ntohl(*(uint32_t *)&reply_header_buffer[8]);
          total_blocks = ntohl(*(uint32_t *)&reply_header_buffer[12]);
          char block_hash[32];
          memcpy(block_hash, &reply_header_buffer[16], 32);
          char total_hash[32];
          memcpy(total_hash, &reply_header_buffer[48], 32);

          // data_recieved += bytes_read;

          // Read message body for current block
          char message_body_buffer[body_length];
          int total_body_read = 0;
          while (total_body_read < body_length) {

            bytes_read =
                compsys_helper_readnb(&state, message_body_buffer, body_length);
            total_body_read += bytes_read;
          }

          // Check the hash of this part of the message
          hashdata_t message_hash;
          get_data_sha(message_body_buffer, message_hash, body_length,
                       SHA256_HASH_SIZE);
          if (memcmp(message_hash, block_hash, SHA256_HASH_SIZE) != 0) {
            printf("Hashes of message body of block %d / %d did not match\n",
                   current_block, total_blocks);
            printf("Data might be corrupted, trying with a new request.\n");
            fclose(file);
            close(clientfd);
            return 0;
          }

          if (bytes_read <= 0) {
            // maybe should have consequenses
            printf("Recieving body segment of multi block file "
                   "failed\n");
            break;
          }

          blocks_recieved++;
          //  To keep track of the final file size
          file_data_recieved += bytes_read;

          // Copy to message buffer to file buffer
          memcpy(&file_buffer[(current_block)*max_body_length],
                 message_body_buffer, body_length);
          printf("Read and copied block %d\n", current_block);
        }

        // Check total message hash with total hash
        hashdata_t total_message_hash;
        get_data_sha(file_buffer, total_message_hash, file_data_recieved,
                     SHA256_HASH_SIZE);
        if (memcmp(total_message_hash, reply_block_total_hash,
                   SHA256_HASH_SIZE) != 0) {
          printf("The hash of the total message and the provided total hash "
                 "didn't match\n");
          printf("Data might be corrupted, trying with a new request.\n");
          fclose(file);
          close(clientfd);
          return 0;
        } else {
          // Write file buffer to file if hashes match
          fwrite(file_buffer, 1, file_data_recieved, file);
        }
        fclose(file);
        close(clientfd);
      }
    }
  }

  return 1;
}

int send_message(NetworkAddress_t peer_address, int command,
                  char *request_body, int request_len) {
// Simple send message over network.
// Creates a new connection and sends a message.
// Creates header, and assembles header and body to message
    int status = 1;
    char *peer_ip = peer_address.ip;
    char peer_port[16];
    sprintf(peer_port, "%d", peer_address.port);

    // Create client socket and connect
    int clientfd = compsys_helper_open_clientfd(peer_ip, peer_port);
    if (clientfd < 0) {
        printf("Connection error, try again\n");
        status = -1;
        return status;
    }

    // Create and populate request header
    RequestHeader_t req_head;
    req_head.port = htonl(my_address->port);
    req_head.command = htonl(command);
    memcpy(req_head.ip, my_address->ip, IP_LEN);
    req_head.length = htonl(request_len);
    memcpy(req_head.signature, my_address->signature, SHA256_HASH_SIZE);

    // Assemble request header and body
    char send_buffer[sizeof(RequestHeader_t) + request_len];

    // Putting request header and message body in buffer to be send
    memcpy(&send_buffer[0], &req_head, sizeof(RequestHeader_t));
    memcpy(&send_buffer[sizeof(RequestHeader_t)], request_body, request_len);

    size_t total_message_length = request_len + sizeof(RequestHeader_t);

    // Send request
    int bytes_send = 0;
    while (bytes_send < total_message_length) {
        int n = compsys_helper_writen(clientfd, send_buffer, total_message_length);
        if (n < 0) {
            printf("Error in sending inform or file request\n");
            return -1;
        }
        bytes_send += n;
    }

    // Handle response if relevant.
    // Command 3 is inform and doesn't expect response
    if (command != 3) {
        printf("passing on to handle_response\n");
        status = handle_response(clientfd, command, request_body, request_len);
    }
    // close connection after response has been handled
    close(clientfd);
    return status;
}



void send_error_message(char* error_message, int error_code, int connfd) {
    // Sends out an error message depending on the error code,
    // and prints appropriate message.
    // TODO - message_buffer to be allocated in the size needed,
    // depending on message.

    char* message_buffer[255];
    int message_length = 0;
    switch (error_code) {
        case 2:
            printf("Peer already exists\n");
            char* message_buffer2 = "Cannot register, peer already exists.\0";
            message_length = strlen(message_buffer2);
            memcpy(message_buffer, message_buffer2, message_length);
            break;
        case 3:
            printf("Peer sending request is not registered in network\n");
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
            message_length = strlen(message_buffer5);
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
  // Assemble reply header and send reply message with error code
    ReplyHeader_t reply_header;;
    reply_header.length = htonl(message_length);
    reply_header.status = htonl(error_code);
    reply_header.this_block = htonl(1);
    reply_header.block_count = htonl(1);

    hashdata_t block_hash;
    get_data_sha(message_buffer, block_hash, message_length, SHA256_HASH_SIZE);
    memcpy(reply_header.block_hash, block_hash, SHA256_HASH_SIZE);
    memcpy(reply_header.total_hash, block_hash, SHA256_HASH_SIZE);

    int total_block_size = sizeof(ReplyHeader_t) + message_length;
    char outputbuffer[total_block_size];
    memcpy(&outputbuffer[0], &reply_header.length, 4);
    memcpy(&outputbuffer[4], &reply_header.status, 4);
    memcpy(&outputbuffer[8], &reply_header.this_block, 4);
    memcpy(&outputbuffer[12], &reply_header.block_count, 4);
    memcpy(&outputbuffer[16], &reply_header.block_hash, 32);
    memcpy(&outputbuffer[48], &reply_header.total_hash, 32);
    memcpy(&outputbuffer[80], message_buffer, message_length);
    compsys_helper_writen(connfd, outputbuffer, total_block_size);
    printf("Error message sent error code %d\n", ntohl(reply_header.status));

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
    while (!not_alone) {
        // Prompts again if no connection, or if someone registered
        // with this peer.
        char peer_ip[IP_LEN];
        fprintf(stdout, "Enter peer IP to connect to: ");
        scanf("%16s", peer_ip);

        // Clean up ip string as otherwise some extra chars can sneak in.
        for (int i=strlen(peer_ip); i<IP_LEN; i++)
            {
                peer_ip[i] = '\0';
            }

        char peer_port[PORT_STR_LEN];
        fprintf(stdout, "Enter peer port to connect to: ");
        scanf("%16s", peer_port);

        // Clean up port string as otherwise some extra chars can sneak in.
        for (int i=strlen(peer_port); i<PORT_STR_LEN; i++) {
            peer_port[i] = '\0';
            }

        NetworkAddress_t* peer_address = malloc(sizeof(NetworkAddress_t));
        memcpy(peer_address->ip, peer_ip, IP_LEN);
        peer_address->port = atoi(peer_port);

        // Send registration request message to peer
        send_message(*peer_address, 1, "", 0);
    }


    while (1) {

        char filename_buffer[255];
        int chars_read = 0;
        fprintf(stdout, "Enter file name to get or type print to print all connected peers: ");
        scanf("%s%n", filename_buffer, &chars_read);

        if (strcmp(filename_buffer, "print") == 0) {
            for (int i = 0; i<peer_count; i++) {
            print_network_address(network[i]);
            }
        }
        pthread_mutex_lock(&lock);
        NetworkAddress_t* random_peer = return_random_peer();
        pthread_mutex_unlock(&lock);
        char filename[chars_read];
        memcpy(filename, filename_buffer, chars_read);
        printf("Requesting file %s from %s:%d\n", filename, random_peer->ip, random_peer->port);

        // Send file request message
        int status = send_message(*random_peer, 2, filename, chars_read-1);
        int identical_requests = 0;
        while ((status == 0) && (identical_requests < 5)) {
            // If file unavailable, try again 5 times
            printf("File unavailable, trying again at another peer.\n");
            random_peer = return_random_peer();
            status = send_message(*random_peer, 2, filename, chars_read-1);
            identical_requests++;
        }
  }    
  
  // You should never see this printed in your finished implementation
  printf("Client thread done\n");

  return NULL;
}


void send_response(uint32_t connfd, uint32_t status, char* response_body, int response_length) {
    // Sends out response to a request recieved in server_thread.
    // Handles status 1 as that means OK. Other status should be handled
    // by send_error_response.
    // Handles responses that fits in one block first by checking length,
    // and otherwise splits it up in multiple blocks

    int max_body_length = MAX_MSG_LEN - (sizeof(ReplyHeader_t));
    int number_of_blocks = (response_length/max_body_length) + 1;
    int size_of_last_block = response_length%max_body_length;
    char block_buffer[number_of_blocks * MAX_MSG_LEN];

    ReplyHeader_t* reply_header = malloc(sizeof(ReplyHeader_t));
    hashdata_t total_hash;


    // Common header attributes no matter the length of the data being sent
    // total hash
    get_data_sha(response_body, total_hash, response_length, SHA256_HASH_SIZE);
    memcpy(reply_header->total_hash, total_hash, SHA256_HASH_SIZE);


    if (response_length < max_body_length) {
        // if data can fit into one block
        // Populate reply header
        reply_header->length = htonl(response_length);
        reply_header->block_count = htonl(1);

        reply_header->this_block = htonl(0);
        reply_header->status = htonl(status);

        memcpy(reply_header->block_hash, total_hash, SHA256_HASH_SIZE);

        // Assemble message to be send as response
        size_t total_response_length = sizeof(ReplyHeader_t) + response_length;
        char *outputbuffer = malloc(total_response_length);
        // TODO - copy fields into outputbuffer, not entire struct
        memcpy(&outputbuffer[0], reply_header, sizeof(ReplyHeader_t));
        memcpy(&outputbuffer[sizeof(ReplyHeader_t)], response_body,
               response_length);

        // TODO - implement while loop to make sure all is written
        // as compsys_helper might be non blocking
        size_t bytes_send = 0;
        size_t n = 0;
        while (bytes_send < total_response_length) {
            n = compsys_helper_writen(connfd, outputbuffer, total_response_length);
            printf("%d bytes written and send, total response length is %zu\n", n,
                   total_response_length);
            if (n < 0) {
                printf("Error in sending response, aborted\n");
                send_error_message("", 7, connfd);
            }
            bytes_send += n;
        }

        // Free output buffer when data is send
        free(outputbuffer);

    } else {

        // If message size is bigger than what fits in one block

        // Populate reply_header for first message.
        reply_header->block_count = htonl(number_of_blocks);
        reply_header->length = htonl(max_body_length);

        // Assemble all but last blocks and put them in block_buffer
        for (int i = 0; i<(number_of_blocks - 1); i++) {
            // Update reply_header with current block number
            reply_header->this_block = htonl(i);

            // Create buffer for this specific blocks data and
            // copy from response_body
            char block_data[max_body_length];
            memcpy(block_data, &response_body[i*max_body_length], max_body_length);

            // Allocate and create block hash to be put in this specific header
            hashdata_t block_hash;
            get_data_sha(block_data, block_hash, max_body_length, SHA256_HASH_SIZE);
            memcpy(reply_header->block_hash, block_hash, SHA256_HASH_SIZE);

            // Copy header to output buffer
            memcpy(&block_buffer[i*MAX_MSG_LEN], &reply_header->length, 4);
            memcpy(&block_buffer[i*MAX_MSG_LEN + 4], &reply_header->status, 4);
            memcpy(&block_buffer[i*MAX_MSG_LEN + 8], &reply_header->this_block, 4);
            memcpy(&block_buffer[i*MAX_MSG_LEN + 12], &reply_header->block_count, 4);
            memcpy(&block_buffer[i*MAX_MSG_LEN + 16], &reply_header->block_hash, 32);
            memcpy(&block_buffer[i*MAX_MSG_LEN + 48], &reply_header->total_hash, 32);

            memcpy(&block_buffer[i*MAX_MSG_LEN + sizeof(ReplyHeader_t)], block_data, max_body_length);
        }

        // Create the last smaller block.

        char block_data[size_of_last_block];
        memcpy(block_data, &response_body[(number_of_blocks-1)*max_body_length], size_of_last_block);

        // Create block hash for last smaller block
        hashdata_t block_hash;
        get_data_sha(block_data, block_hash, size_of_last_block, SHA256_HASH_SIZE);
        // Populate reply header
        // Total hash and total block count already set.
        memcpy(reply_header->block_hash, block_hash, SHA256_HASH_SIZE);
        reply_header->length = htonl(size_of_last_block);
        reply_header->this_block = htonl(number_of_blocks-1);

        // Copy into block buffer
        //memcpy(&block_buffer[(number_of_blocks-1)*MAX_MSG_LEN], reply_header, sizeof(ReplyHeader_t));

        memcpy(&block_buffer[(number_of_blocks-1)*MAX_MSG_LEN], &reply_header->length, 4);
        memcpy(&block_buffer[(number_of_blocks-1)*MAX_MSG_LEN + 4], &reply_header->status, 4);
        memcpy(&block_buffer[(number_of_blocks-1)*MAX_MSG_LEN + 8], &reply_header->this_block, 4);
        memcpy(&block_buffer[(number_of_blocks-1)*MAX_MSG_LEN + 12], &reply_header->block_count, 4);
        memcpy(&block_buffer[(number_of_blocks-1)*MAX_MSG_LEN + 16], &reply_header->block_hash, 32);
        memcpy(&block_buffer[(number_of_blocks-1)*MAX_MSG_LEN + 48], &reply_header->total_hash, 32);

        memcpy(&block_buffer[(number_of_blocks-1)*MAX_MSG_LEN + sizeof(ReplyHeader_t)], block_data, size_of_last_block);


        // Random order for sending blocks
        // Seed random generator
        srand(time(NULL));

        int random_order[number_of_blocks];
        for (int i = 0; i<number_of_blocks; i++) {
            random_order[i] = i;
        }
        shuffle(random_order, number_of_blocks);


        // Send blocks to peer in random order
        for (int block = 0; block < number_of_blocks; block++) {
            int random_block = random_order[block];
            char send_buffer[MAX_MSG_LEN];
            // Check that it is not the last block, as the length is different
            if (random_block < (number_of_blocks-1)) {
                // If not last block, send the MAX_MSG_LEN
                // Copy block from block buffer to send buffer, random_block is index
                memcpy(send_buffer, &block_buffer[random_block * MAX_MSG_LEN],
                       MAX_MSG_LEN);

                int bytes_send = compsys_helper_writen(connfd, send_buffer, MAX_MSG_LEN);
                printf("Block %d / %d: %d bytes written and send, block size is %d\n",
                       random_block, number_of_blocks, bytes_send, MAX_MSG_LEN);
            } else {

                // If last block, shorter length but random_block is still index
                memcpy(send_buffer, &block_buffer[random_block * MAX_MSG_LEN],
                       size_of_last_block+sizeof(ReplyHeader_t));
                int bytes_send = compsys_helper_writen(connfd, send_buffer, size_of_last_block+sizeof(ReplyHeader_t));
                printf("Block %d / %d: %d bytes written and send for last block. Block size is %lu\n",
                       random_block, number_of_blocks, bytes_send, (size_of_last_block+sizeof(ReplyHeader_t)));
            }
        }

    }

    free(reply_header);
}
void handle_inform_message(RequestHeader_t* inform_header, char* inform_body) {
    // inform_body must be 68 bytes!!
    // Check if message is from valid source

    if (is_valid_ip(inform_header->ip)
        && is_valid_port(inform_header->port)) {
        // Create new network address for network array
        NetworkAddress_t* new_peer = malloc(sizeof(NetworkAddress_t));
        memcpy(new_peer->ip, &inform_body[0], 16);

        uint32_t port_network_order;
        memcpy(&port_network_order, &inform_body[16], 4);
        new_peer->port = ntohl(port_network_order);
        char salt[SALT_LEN];
        memcpy(new_peer->signature, &inform_body[20], 32);
        memcpy(salt, &inform_body[52], 16);
        memcpy(new_peer->salt, salt, SALT_LEN);


        pthread_mutex_lock(&lock);
        while (!is_registered && !not_alone) {

            pthread_cond_wait(&cond, &lock);
        }
        if (!is_in_network(network, new_peer, peer_count)) {
          NetworkAddress_t **new_network =
              realloc(network, sizeof(NetworkAddress_t*) * (peer_count + 1));
          if (new_network == NULL) {
            printf("Memory allocation problem.\n");
            free(new_peer);
            return;
          } else {
            network = new_network;
          }

          network[peer_count] = new_peer;
          peer_count++;
          printf("Updating network on inform.\n Number of peers %d\n",
                 peer_count);
        } else {
          printf("Peer from inform request was already registered.\n");
        }
        printf("about to print\n");

        for (int n = 0; n < peer_count; n++) {
          print_network_address(network[n]);
        }
        pthread_mutex_unlock(&lock);
    }
}


void handle_register_message(RequestHeader_t* register_header, int connfd) {

    if (is_valid_ip(register_header->ip) && is_valid_port(register_header->port)) {
        // Create new network address for new peer
        NetworkAddress_t* new_peer = malloc(sizeof(NetworkAddress_t));
        if (new_peer == NULL) {
            printf("Memory allocation problem while registrering new peer.\n");
            return;
        }
        new_peer->port = register_header->port;
        memcpy(new_peer->ip, register_header->ip, 16);

        // Generate network saved signature with random salt
        char random_salt[SALT_LEN];
        generate_random_salt(random_salt);

        // Create network signature from register request signature and random salt.
        get_signature(register_header->signature, SHA256_HASH_SIZE, random_salt, &new_peer->signature);
        memcpy(new_peer->salt, random_salt, SALT_LEN);

        // Add to network and increment peer count and reallocate memory for network
        pthread_mutex_lock(&lock);

        NetworkAddress_t** new_network = realloc(network, sizeof(NetworkAddress_t*)*(peer_count + 1));
        if (new_network == NULL) {
            printf("Memory allocation problem while registrering.\n");
            free(new_peer);
            return;
        } else {
            network = new_network;
        }

        if (!is_in_network(network, new_peer, peer_count)) {
            network[peer_count] = new_peer;
            peer_count++;
        }
        // Print out result
        printf("Network updated after register message\n");
        for (int i = 0; i < peer_count; i++) {
            print_network_address(network[i]);
        }
        // We are not alone anymore
        not_alone = 1;

        // Prepare a response to registration
        size_t response_length = 68 * peer_count;
        char response_body[response_length];

        // Copy entire network into buffer to send as response
        // Here we're still sending the peer that has just been registered,
        // that is it is in the network, but it's probably ok, as it can check
        // for it self and sort it out.
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
              // Do not send inform message to newly registered peer

              // Allocate memory for inform message
              char inform_body[sizeof(NetworkAddress_t)];


              // Assemble body with info on new peer in network
              uint32_t new_peer_port = htonl(new_peer->port);
              memcpy(&inform_body[0], new_peer->ip, 16);
              memcpy(&inform_body[16], &new_peer_port, 4);
              memcpy(&inform_body[20], new_peer->signature, 32);
              memcpy(&inform_body[52], new_peer->salt, 16);

              send_message(*network[peer], 3, inform_body, sizeof(NetworkAddress_t));
            }
        }
        pthread_mutex_unlock(&lock);
        // Do not free new_peer as it is to be saved as a pointer
        // in network array. Should be freed on teardown.
    }
}

void handle_file_request(RequestHeader_t* file_request_header, int connfd, char* file_request_body) {

    int body_length = file_request_header->length;
    char filename[body_length+1];
    FILE *file;
    //char* buffer;
    uint32_t file_size;
    size_t bytes_read;

    // Get name of file from request
    memcpy(filename, file_request_body, body_length);
    filename[body_length] = '\0';
    // Check filename safety
    if (!is_safe_filename(filename)) {
        printf("Requested filename was unsafe!\n");
        send_error_message("Unsafe file request, closing connection!\n", 7, connfd);
        close(connfd);
        return;
    }

    // Open requested file
    file = fopen(filename, "r");
    if (file == NULL) {
        printf("Could not open requested file\n");
        send_error_message("File doesn't exist in peer\n", 5, connfd);
        return;
    }

    // Find file size
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    rewind(file);

    // Buffer for file content
    char buffer[file_size];

    // Read file into buffer
    bytes_read = fread(buffer, 1, file_size, file);

    fclose(file);

    printf("Sending file %s as response to request. bytes_read: %zu and file size is %d\n", filename, bytes_read, file_size);
    send_response(connfd, 1, buffer, bytes_read);

}

void* handle_server_request(void* arg) {

    // Function for thread to handle server request.
    // Spawned and initiated from main server thread.

    pthread_detach(pthread_self());
    // Copy connection fd from arg and free memory
    request_thread_args_t* args = (request_thread_args_t*) arg;
    int request_connfd = args->request_connfd;
    free(arg);

    // Allocate memory for request header
    RequestHeader_t request_header;
    compsys_helper_state_t state;
    char request_header_buffer[REQUEST_HEADER_LEN];

    // read request header
    compsys_helper_readinitb(&state, request_connfd);
    int bytes_read = 0;
    while (bytes_read < REQUEST_HEADER_LEN) {
        int n = compsys_helper_readnb(&state, request_header_buffer, REQUEST_HEADER_LEN);
        if (n < 0) {
            printf("Error reading incoming server request header, aborting.\n");
            pthread_mutex_lock(&lock);
            active_threads--;
            pthread_mutex_unlock(&lock);
            return NULL;
        }
        bytes_read += n;
    }

    // Parse request header data and populate
    // request header struct
    char request_ip[16];
    memcpy(request_ip, &request_header_buffer[0], 16);
    uint32_t request_port = ntohl(*(uint32_t*)&request_header_buffer[16]);
    char request_signature[32];
    memcpy(request_signature, &request_header_buffer[20], 32);
    uint32_t request_command = ntohl(*(uint32_t*)&request_header_buffer[52]);
    uint32_t request_body_length = ntohl(*(uint32_t*)&request_header_buffer[56]);

    // Put it all into request header struct
    request_header.length = request_body_length;
    request_header.command = request_command;
    memcpy(request_header.ip, request_ip, 16);
    request_header.port = request_port;
    memcpy(request_header.signature, request_signature, 32);


    if (!is_valid_ip(request_ip) || !is_valid_port(request_port)) {
        printf("Request was not with a valid IP or port.\n");
        send_error_message("", 7, request_connfd);

        pthread_mutex_lock(&lock);
        active_threads--;
        pthread_mutex_unlock(&lock);
        return NULL;
    }
    // Read request body - if there is any
    char request_body[request_body_length];
    compsys_helper_readnb(&state, &request_body, request_body_length);
    printf("Handling server request with command: %d\n", request_command);



    NetworkAddress_t requesting_peer;
    memcpy(&requesting_peer.ip, request_ip, IP_LEN);
    requesting_peer.port = request_port;

    // Handle request based on request command
    if (request_command == 1) {
        // if there is no one in network, this must be the first peer
        // must be locked if there is a rapid influx of registrations to same peer
        if (peer_count == 0) {

        pthread_mutex_lock(&lock);
          // Generate network saved signature of my signature
          // to be send out to the peers.
          printf("Assuming i'm the first peer\n");
          // Make room for new peers in network[]
          NetworkAddress_t** new_network = realloc(network, sizeof(NetworkAddress_t*) * (peer_count + 1));

          if (new_network == NULL) {
            printf("Memory allocation problem.\n");
            active_threads--;
            pthread_mutex_unlock(&lock);
            return NULL;

          } else {
              network = new_network;
          }

          char random_salt[SALT_LEN];
          generate_random_salt(random_salt);

          hashdata_t network_saved_signature;
          get_signature(my_address->signature, SHA256_HASH_SIZE, random_salt,
                        &network_saved_signature);
          NetworkAddress_t *my_self_in_network =
              malloc(sizeof(NetworkAddress_t));
          my_self_in_network->port = my_address->port;
          memcpy(my_self_in_network->ip, my_address->ip, IP_LEN);
          memcpy(my_self_in_network->salt, random_salt, SALT_LEN);
          memcpy(my_self_in_network->signature, network_saved_signature,
                 SHA256_HASH_SIZE);
          network[0] = my_self_in_network;
          peer_count++;
          not_alone = 1;

        pthread_mutex_unlock(&lock);
        }
        // is_in_network needs to be locked
        pthread_mutex_lock(&lock);
        int requesting_peer_is_in_network = is_in_network(network, &requesting_peer, peer_count);
        pthread_mutex_unlock(&lock);

        if (requesting_peer_is_in_network) {
            // If registering peer already registered send error response and stop.
            send_error_message("Peer already registered in network\0", 2, request_connfd);
            printf("Peer trying to register was already registered in network.\n");

        } else {

          printf("Incoming registration request from IP: %s Port: %d\n", request_ip, request_port);
          handle_register_message(&request_header, request_connfd);
        }
      // Exit after handling the register message.
      // handle_register_message sends out a response


    } else if (request_command == 2) {
      // File request
      // Calculate hash of incoming signature
      hashdata_t incoming_signature_hash;

      NetworkAddress_t *requesting_peer_info = malloc(sizeof(NetworkAddress_t));

      pthread_mutex_lock(&lock);
      find_in_network(&requesting_peer, requesting_peer_info);
      int requesting_peer_is_in_network = is_in_network(network, &requesting_peer, peer_count);
      pthread_mutex_unlock(&lock);

      get_signature(request_signature, SHA256_HASH_SIZE,
                    requesting_peer_info->salt, &incoming_signature_hash);

      if (!requesting_peer_is_in_network) {
        // If not in network, send error message and stop.
        send_error_message("Not registered in network.\0", 3, request_connfd);
        printf("Peer requesting was not registered in network.\n");

      // Check if hashes match
      } else if (memcmp(incoming_signature_hash, requesting_peer_info->signature,
                 SHA256_HASH_SIZE) != 0) {
        // Hashes didn't match, send error
        printf("Password mismatch\n");
        send_error_message("Password mismatch\0", 4, request_connfd);

      } else {
        // If no error handle file request by passing on to handle_file_request
        printf("Incoming file request from IP: %s Port: %d\n", request_ip,
               request_port);
        handle_file_request(&request_header, request_connfd, request_body);
      }

      free(requesting_peer_info);

    }   else if (request_command == 3) {
        // Inform request
        // If body is the wrong length, send error, else handle it
        // by passing it on to function. After that exit.
        // Calculate hash of incoming signature
        hashdata_t incoming_signature_hash;

        NetworkAddress_t *requesting_peer_info = malloc(sizeof(NetworkAddress_t));

        pthread_mutex_lock(&lock);
        find_in_network(&requesting_peer, requesting_peer_info);
        int requesting_peer_is_in_network = is_in_network(network, &requesting_peer, peer_count);
        pthread_mutex_unlock(&lock);

        get_signature(request_signature, SHA256_HASH_SIZE,
                    requesting_peer_info->salt, &incoming_signature_hash);

        if ((request_body_length % 68) != 0) {
            printf("Inform request body is the wrong length. It is: %d\n", request_body_length);
            send_error_message("", 7, request_connfd);

        } else if (!requesting_peer_is_in_network) {
          // if not registered, send error - even though it's just inform
          send_error_message("Informing peer not registered in network.\0", 3, request_connfd);

        } else if (memcmp(incoming_signature_hash, requesting_peer_info->signature, SHA256_HASH_SIZE) != 0) {
            // Password mismatch
            send_error_message("Password mismatch\0", 4, request_connfd);

        } else {
          handle_inform_message(&request_header, request_body);
        }
        free(requesting_peer_info);

    } else {

      printf("Incoming request command wasn't understood\n");
      send_error_message("", 7, request_connfd);

    }

    pthread_mutex_lock(&lock);
    active_threads--;
    pthread_mutex_unlock(&lock);
    return NULL;
}

/*
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 */
void* server_thread() {
    // Main server thread. Listening for connections
    // and spawns threads to handle requests.
  int connfd;
  char local_port[16];
  int listenfd;

  // Incoming connection threads
  int max_requests = 10;
  pthread_t connection_threads[max_requests];
  struct sockaddr_storage clientaddr;
  struct sockaddr_in listen_address;
  int lis_addr_len = sizeof(listen_address);
  sprintf(local_port, "%d", my_address->port);
  listenfd = compsys_helper_open_listenfd(local_port);

  while (1) {
      // Check if max requests have been reached.
      while (active_threads < max_requests) {
      // Accept incomint connections
          if ((connfd = accept(listenfd, (struct sockaddr*) &clientaddr, (socklen_t*) &lis_addr_len)) < 0) {
              printf("error in accepting server request\n");
          }
        request_thread_args_t* arg = malloc(sizeof(request_thread_args_t));
        arg->request_connfd = connfd;
        pthread_create(&connection_threads[active_threads], NULL, handle_server_request, (void*)arg);
        // thread copies and frees its arg, so no free needed here.

        pthread_mutex_lock(&lock);
        active_threads++;
        pthread_mutex_unlock(&lock);
      }
  }
  // You should never see this printed in your finished implementation
  printf("Server thread done\n");

  return NULL;
}

void free_addresses_in_network() {
    for (int i = 0; i < peer_count; i++) {
        free(network[i]);
    }
    free(network);
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
    char salt[SALT_LEN];
    generate_random_salt(salt);
    // Ved registrering:
    memcpy(my_address->salt, salt, SALT_LEN);

    // Create a signature from password and salt, and store in signature    
    hashdata_t signature;
    get_signature(password, strlen(password), salt, &signature);

    network = malloc(sizeof(NetworkAddress_t*));
    if (network == NULL) {
        printf("Memory allocation problem on startup.\n");
        return -1;
    }
    memcpy(my_address->signature, signature, SHA256_HASH_SIZE);

    // Setup the client and server threads
    pthread_t client_thread_id;
    pthread_t server_thread_id;
    pthread_create(&client_thread_id, NULL, client_thread, NULL);
    printf("Client started\n");
    pthread_create(&server_thread_id, NULL, server_thread, NULL);
    printf("Server started\n");
    // Wait for them to complete. 
    pthread_join(client_thread_id, NULL);
    pthread_join(server_thread_id, NULL);

    // Function to free all network address pointers in network[]
    free_addresses_in_network();
    //free(network);
    printf("Exit program\n");
    exit(EXIT_SUCCESS);
}
