#include "common.h"
#include "sha256.h"
#include "network.h"
#include "security.h"
#include "utils.h"
#include "messages.h"
#include "request_handlers.h"

#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
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


int main(int argc, char **argv) {
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
