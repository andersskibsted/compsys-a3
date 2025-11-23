#ifndef NETWORK_H_
#define NETWORK_H_

#include "peer.h"
#include <stdint.h>

void make_network_address_from_response(void* data, NetworkAddress_t* new_peer, int offset);

int is_in_network(NetworkAddress_t** network, NetworkAddress_t* peer, int number_of_peers);

int is_same_peer(NetworkAddress_t* peer1, NetworkAddress_t* peer2);

int is_same_ip_and_port(char* ip1, int port1, char* ip2, int port2);

int find_in_network(NetworkAddress_t* peer_to_match, NetworkAddress_t* new_peer_location);

NetworkAddress_t* return_random_peer(void);

void print_network_address(NetworkAddress_t* address);

void print_peers(char* data, size_t data_len);

#endif // NETWORK_H_
