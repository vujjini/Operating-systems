#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>

#include "hash_functions.h"

#define KEEP 16 // only the first 16 bytes of a hash are kept
#define MAX_THREADS 11

struct cracked_hash {
    char hash[2 * KEEP + 1];
    char *password, *alg;
};

typedef unsigned char * (*hashing)(unsigned char *, unsigned int);

int n_algs = 4;
hashing fn[4] = { calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512 };
char *algs[4] = { "MD5", "SHA1", "SHA256", "SHA512" };

int n_hashed = 0;
struct cracked_hash *cracked_hashes;
pthread_mutex_t lock;

int compare_hashes(char *a, char *b) {
    for (int i = 0; i < 2 * KEEP; i++) {
        if (a[i] != b[i])
            return 0;
    }
    return 1;
}

typedef struct {
    char **passwords;
    int start;
    int end;
} thread_arg_t;

void *worker(void *arg) {
    thread_arg_t *data = (thread_arg_t *)arg;
    char hex_hash[2 * KEEP + 1];
    
    for (int p = data->start; p < data->end; ++p) {
        char *password = data->passwords[p];
        
        for (int i = 0; i < n_algs; i++) {
            unsigned char *hash = fn[i]((unsigned char *)password, strlen(password));
            for (int j = 0; j < KEEP; j++) {
                sprintf(&hex_hash[2 * j], "%02x", hash[j]);
            }
            
            // Compare this computed hash with all target hashes.
            for (int k = 0; k < n_hashed; k++) {
                if (compare_hashes(hex_hash, cracked_hashes[k].hash)) {
                    pthread_mutex_lock(&lock);
                    if (cracked_hashes[k].password == NULL) {
                        cracked_hashes[k].password = strdup(password);
                        cracked_hashes[k].alg = algs[i];
                    }
                    pthread_mutex_unlock(&lock);
                }
            }
        }
    }
    return NULL;
}

void crack_hashed_passwords(char *password_list, char *hashed_list, char *output) {
    FILE *fp;
    char line[256];

    // Load hashed passwords.
    fp = fopen(hashed_list, "r");
    assert(fp != NULL);
    while (fscanf(fp, "%s", line) == 1)
        n_hashed++;
    rewind(fp);
    cracked_hashes = malloc(n_hashed * sizeof(struct cracked_hash));
    assert(cracked_hashes != NULL);
    for (int i = 0; i < n_hashed; i++) {
        fscanf(fp, "%s", cracked_hashes[i].hash);
        cracked_hashes[i].password = NULL;
        cracked_hashes[i].alg = NULL;
    }
    fclose(fp);

    // Load common passwords into memory.
    fp = fopen(password_list, "r");
    assert(fp != NULL);
    int n_passwords = 0, capacity = 1024;
    char **passwords = malloc(capacity * sizeof(char *));
    while (fscanf(fp, "%s", line) == 1) {
        if (n_passwords >= capacity) {
            capacity *= 2;
            passwords = realloc(passwords, capacity * sizeof(char *));
        }
        passwords[n_passwords++] = strdup(line);
    }
    fclose(fp);

    // Set up threading.
    pthread_t threads[MAX_THREADS];
    thread_arg_t args[MAX_THREADS];
    pthread_mutex_init(&lock, NULL);
    
    int batch_size = (n_passwords + MAX_THREADS - 1) / MAX_THREADS;
    int t;
    for (t = 0; t < MAX_THREADS && t * batch_size < n_passwords; t++) {
        args[t].passwords = passwords;
        args[t].start = t * batch_size;
        args[t].end = ((t + 1) * batch_size < n_passwords) ? (t + 1) * batch_size : n_passwords;
        pthread_create(&threads[t], NULL, worker, &args[t]);
    }
    for (int i = 0; i < t; i++)
        pthread_join(threads[i], NULL);
    pthread_mutex_destroy(&lock);

    // Output results: one line per hash in the same order as in the hashed_list.
    fp = fopen(output, "w");
    assert(fp != NULL);
    for (int i = 0; i < n_hashed; i++) {
        if (cracked_hashes[i].password)
            fprintf(fp, "%s:%s\n", cracked_hashes[i].password, cracked_hashes[i].alg);
        else
            fprintf(fp, "not found\n");
    }
    fclose(fp);

    // Cleanup.
    for (int i = 0; i < n_passwords; i++)
        free(passwords[i]);
    free(passwords);
    free(cracked_hashes);
}
