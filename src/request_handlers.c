#include "request_handlers.h"

#include "peer.h"
#include "network.h"
#include "security.h"
#include "messages.h"
#include <sys/_pthread/_pthread_mutex_t.h>

extern pthread_mutex_t lock;
extern pthread_cond_t cond;
extern NetworkAddress_t* my_address;
extern NetworkAddress_t** network;
extern uint32_t peer_count;
extern int not_alone;
extern int active_threads;
extern int is_registered;



void handle_register_request(RequestHeader_t* register_header, int connfd) {

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


void handle_inform_request(RequestHeader_t* inform_header, char* inform_body) {
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

        for (int n = 0; n < peer_count; n++) {
          print_network_address(network[n]);
        }
        pthread_mutex_unlock(&lock);
    }
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
        printf("after is_in_network\n");

        if (requesting_peer_is_in_network) {
            // If registering peer already registered send error response and stop.
            send_error_message("Peer already registered in network\0", 2, request_connfd);
            printf("Peer trying to register was already registered in network.\n");

        } else {

          printf("Incoming registration request from IP: %s Port: %d\n", request_ip, request_port);
          handle_register_request(&request_header, request_connfd);
        }
      // Exit after handling the register message.
      // handle_register_register sends out a response


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
          handle_inform_request(&request_header, request_body);
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
