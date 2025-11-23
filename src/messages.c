#include "messages.h"
#include "network.h"
#include "peer.h"
#include "utils.h"

#include <stdint.h>
#include <sys/_pthread/_pthread_cond_t.h>
#include <sys/_pthread/_pthread_mutex_t.h>


extern pthread_mutex_t lock;
extern pthread_cond_t cond;

extern NetworkAddress_t** network;
extern NetworkAddress_t* my_address;
extern uint32_t peer_count;

extern int is_registered;
extern int not_alone;

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
        make_network_address_from_response(message_buf, peer, i * 68);

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
        status = handle_response(clientfd, command, request_body, request_len);
    }
    // close connection after response has been handled
    close(clientfd);
    return status;
}



void send_error_message(char* error_message, int error_code, int connfd) {
    // Sends out an error message depending on the error code,
    // and prints appropriate message.

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
        memcpy(&outputbuffer[0], reply_header, sizeof(ReplyHeader_t));
        memcpy(&outputbuffer[sizeof(ReplyHeader_t)], response_body,
               response_length);

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
