#include "security.h"
#include <ctype.h>


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
