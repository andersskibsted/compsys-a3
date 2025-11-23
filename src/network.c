#include "network.h"
#include "common.h"
#include "peer.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>


extern NetworkAddress_t *my_address;
extern NetworkAddress_t** network;
extern uint32_t peer_count;

void make_network_address_from_response(void *data, NetworkAddress_t* new_peer, int offset) {
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
