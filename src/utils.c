#include "utils.h"
#include "peer.h"
#include <stdint.h>


extern NetworkAddress_t** network;
extern uint32_t peer_count;

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

void free_addresses_in_network() {
    for (int i = 0; i < peer_count; i++) {
        free(network[i]);
    }
    free(network);
}
