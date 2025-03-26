// #include <stdio.h>
// #include <string.h>
// #include <stdlib.h>
// #include <assert.h>

// // #include "hmap.h"

// #include "hash_functions.h"

// #define KEEP 16 // only the first 16 bytes of a hash are kept
// #define HASH_SIZE 8388607  // Large prime number for better distribution

// // Structure for storing password details
// typedef struct cracked_hash {
//     char *password;
//     char *alg;
// } cracked_hash;

// // Node structure for separate chaining
// typedef struct hash_node {
//     char key[2 * KEEP + 1];  // Hash key
//     cracked_hash value;
//     struct hash_node *next;
// } hash_node;

// // Hash table
// typedef struct {
//     hash_node **buckets;
// } hash_map;

// // Function prototypes
// hash_map* create_hash_map();
// void insert_hash_map(hash_map *map, const char *key, const char *password, const char *alg);
// cracked_hash* get_hash_map(hash_map *map, const char *key);
// void delete_hash_map(hash_map *map, const char *key);
// void free_hash_map(hash_map *map);

// struct cracked_hash_details {
// 	char hash[2*KEEP+1];
// 	char *password, *alg;
// };


// typedef unsigned char * (*hashing)(unsigned char *, unsigned int);

// int n_algs = 4;
// hashing fn[4] = {calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512};
// char *algs[4] = {"MD5", "SHA1", "SHA256", "SHA512"};

// int compare_hashes(char *a, char *b) {
// 	for(int i=0; i < 2*KEEP; i++)
// 		if(a[i] != b[i])
// 			return 0;
// 	return 1;
// }


// // Function name: crack_hashed_passwords
// // Description:   Computes different hashes for each password in the password list,
// //                then compare them to the hashed passwords to decide whether if
// //                any of them matches this password. When multiple passwords match
// //                the same hash, only the first one in the list is printed.
// void crack_hashed_passwords(char *password_list, char *hashed_list, char *output) {
// 	// ht* table = ht_create();
// 	// if (!table) {
//     //     printf("Failed to create hash table\n");
//     //     exit(0);
//     // }

// 	hash_map *map = create_hash_map();



// 	FILE *fp;
// 	char password[256];  // passwords have at most 255 characters
// 	char hex_hash[2*KEEP+1]; // hashed passwords have at most 'keep' characters

// 	// load hashed passwords
// 	int n_hashed = 0;
// 	struct cracked_hash_details *cracked_hashes;
// 	fp = fopen(hashed_list, "r");
// 	assert(fp != NULL);
// 	while(fscanf(fp, "%s", hex_hash) == 1)
// 		n_hashed++;
// 	rewind(fp);
// 	cracked_hashes = (struct cracked_hash_details *) malloc(n_hashed*sizeof(struct cracked_hash_details));
// 	assert(cracked_hashes != NULL);
// 	for(int i=0; i < n_hashed; i++) {
// 		fscanf(fp, "%s", cracked_hashes[i].hash);
// 		cracked_hashes[i].password = NULL;
// 		cracked_hashes[i].alg = NULL;
// 	}
// 	fclose(fp);

// 	// load common passwords, hash them, and compare them to hashed passwords
// 	fp = fopen(password_list, "r");
// 	assert(fp != NULL);
// 	while(fscanf(fp, "%s", password) == 1) {

// 		for(int i=0; i < n_algs; i++) {
// 			unsigned char *hash = fn[i]((unsigned char *)password, strlen(password));
// 			for(int j=0; j < KEEP; j++)
// 				sprintf(&hex_hash[2*j], "%02x", hash[j]);
// 			hex_hash[2*KEEP] = '\0';
// 			// struct cracked_hash hash1 = {password, algs[i]};
// 			// struct cracked_hash *exists = ht_get(table, hex_hash);
// 			cracked_hash *exists = get_hash_map(map, hex_hash);
// 			if (exists != NULL){
// 				continue;
// 			}
// 			else{
// 				// ht_set(table, hex_hash, hash1);
// 				insert_hash_map(map, hex_hash, password, algs[i]);
// 			}

// 			free(hash);
// 		}
// 	}


// 	// // fix the way the hash is found
// 	for(int j=0; j < n_hashed; j++) {
// 		if(cracked_hashes[j].password !=  NULL){
// 			continue;
// 		}
// 		// struct cracked_hash *result = ht_get(table, cracked_hashes[j].hash);
// 		// if(result) {
// 		// 	cracked_hashes[j].password = strdup(result->password);
// 		// 	cracked_hashes[j].alg = result->alg;
// 		// }
// 		cracked_hash *result = get_hash_map(map, cracked_hashes[j].hash);
// 		if (result){
// 			cracked_hashes[j].password = strdup(result->password);
// 			cracked_hashes[j].alg = result->alg;
// 		}
// 	}
// 	fclose(fp);

// 	// print results
// 	fp = fopen(output, "w");
// 	assert(fp != NULL);
// 	for(int i=0; i < n_hashed; i++) {
// 		if(cracked_hashes[i].password ==  NULL)
// 			fprintf(fp, "not found\n");
// 		else
// 			fprintf(fp, "%s:%s\n", cracked_hashes[i].password, cracked_hashes[i].alg);
// 	}
// 	fclose(fp);

// 	// release stuff
// 	for(int i=0; i < n_hashed; i++)
// 		free(cracked_hashes[i].password);
// 	free(cracked_hashes);
// 	free_hash_map(map);
// }



// // Hash function (djb2 algorithm)
// unsigned long hash_function(const char *str) {
//     unsigned long hash = 5381;
//     int c;
//     while ((c = *str++))
//         hash = ((hash << 5) + hash) + c;
//     return hash % HASH_SIZE;
// }

// // Create a new hash map
// hash_map* create_hash_map() {
//     hash_map *map = malloc(sizeof(hash_map));
//     if (!map) {
//         perror("Failed to allocate hash map");
//         exit(EXIT_FAILURE);
//     }
//     map->buckets = calloc(HASH_SIZE, sizeof(hash_node *));
//     if (!map->buckets) {
//         perror("Failed to allocate hash map buckets");
//         free(map);
//         exit(EXIT_FAILURE);
//     }
//     return map;
// }

// // Insert into hash map
// void insert_hash_map(hash_map *map, const char *key, const char *password, const char *alg) {
//     unsigned long index = hash_function(key);
//     hash_node *new_node = malloc(sizeof(hash_node));
//     if (!new_node) {
//         perror("Failed to allocate node");
//         exit(EXIT_FAILURE);
//     }
    
//     strncpy(new_node->key, key, 2 * KEEP);
//     new_node->key[2 * KEEP] = '\0';
    
//     new_node->value.password = strdup(password);
//     new_node->value.alg = strdup(alg);
//     new_node->next = map->buckets[index];
//     map->buckets[index] = new_node;
// }

// // Retrieve from hash map
// cracked_hash* get_hash_map(hash_map *map, const char *key) {
//     unsigned long index = hash_function(key);
//     hash_node *node = map->buckets[index];
//     while (node) {
//         if (strcmp(node->key, key) == 0) {
//             return &node->value;
//         }
//         node = node->next;
//     }
//     return NULL;
// }

// // Delete from hash map
// void delete_hash_map(hash_map *map, const char *key) {
//     unsigned long index = hash_function(key);
//     hash_node *node = map->buckets[index];
//     hash_node *prev = NULL;

//     while (node) {
//         if (strcmp(node->key, key) == 0) {
//             if (prev) {
//                 prev->next = node->next;
//             } else {
//                 map->buckets[index] = node->next;
//             }
//             free(node->value.password);
//             free(node->value.alg);
//             free(node);
//             return;
//         }
//         prev = node;
//         node = node->next;
//     }
// }

// // Free hash map
// void free_hash_map(hash_map *map) {
//     for (int i = 0; i < HASH_SIZE; i++) {
//         hash_node *node = map->buckets[i];
//         while (node) {
//             hash_node *temp = node;
//             node = node->next;
//             free(temp->value.password);
//             free(temp->value.alg);
//             free(temp);
//         }
//     }
//     free(map->buckets);
//     free(map);
// }

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>

#include "hash_functions.h"

#define KEEP 16 // only the first 16 bytes of a hash are kept
#define HASH_SIZE 8388607  // Large prime number for better distribution
// pthread_mutex_t hash_map_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_rwlock_t hash_map_rwlock = PTHREAD_RWLOCK_INITIALIZER;

pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;

// Structure for storing password details
typedef struct cracked_hash {
    char *password;
    char *alg;
    int index;
} cracked_hash;

// Node structure for separate chaining
typedef struct hash_node {
    char key[2 * KEEP + 1];  // Hash key
    cracked_hash value;
    struct hash_node *next;
} hash_node;

// Hash table
typedef struct {
    hash_node **buckets;
} hash_map;

// Function prototypes
hash_map* create_hash_map();
void insert_hash_map(hash_map *map, const char *key, const char *password, const char *alg, int index);
cracked_hash* get_hash_map(hash_map *map, const char *key);
void delete_hash_map(hash_map *map, const char *key);
void free_hash_map(hash_map *map);

struct cracked_hash_details {
    char hash[2 * KEEP + 1];
    char *password, *alg;
};

typedef unsigned char *(*hashing)(unsigned char *, unsigned int);

int n_algs = 4;
hashing fn[4] = {calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512};
char *algs[4] = {"MD5", "SHA1", "SHA256", "SHA512"};

int compare_hashes(char *a, char *b) {
    for (int i = 0; i < 2 * KEEP; i++)
        if (a[i] != b[i])
            return 0;
    return 1;
}

// Structure to hold the data for each thread
typedef struct {
    // hash_map *map;
    hash_map *cracked_map;
    struct cracked_hash_details *cracked_hashes;
    char **passwords; // Array of passwords
    int start_index;
    int end_index;
} thread_data;

// Thread function to process a portion of the password list
void* crack_passwords_thread(void *arg) {
    thread_data *data = (thread_data *)arg;
    char hex_hash[2 * KEEP + 1]; // Hashed passwords
    // FILE *fp;
    // fp = fopen(data->output, "a");
    // assert(fp != NULL);

    for (int i = data->start_index; i < data->end_index; i++) {
        char *password = data->passwords[i];

        for (int j = 0; j < n_algs; j++) {
            unsigned char *hash = fn[j]((unsigned char *)password, strlen(password));
            for (int k = 0; k < KEEP; k++)
                sprintf(&hex_hash[2 * k], "%02x", hash[k]);
            hex_hash[2 * KEEP] = '\0';

            // Check if hash already exists
            // cracked_hash *exists = get_hash_map(data->map, hex_hash);
            // if (exists == NULL) {
            //     insert_hash_map(data->map, hex_hash, password, algs[j]);
            // }
            // pthread_mutex_lock(&hash_map_lock);
            pthread_rwlock_rdlock(&hash_map_rwlock);  
            cracked_hash *exists = get_hash_map(data->cracked_map, hex_hash);
            pthread_rwlock_unlock(&hash_map_rwlock);
            // pthread_mutex_unlock(&hash_map_lock);
            // pthread_mutex_lock(&file_mutex);  
            if (exists){
                if (exists->password != NULL){
                    // fprintf(fp, "not found\n");
                    continue;
                }
                // fprintf(fp, "%s:%s\n", password, algs[j]);
                // pthread_mutex_lock(&hash_map_lock);
                pthread_rwlock_rdlock(&hash_map_rwlock);  
                data->cracked_hashes[exists->index].password = strdup(password);
                data->cracked_hashes[exists->index].alg = strdup(algs[j]);
                insert_hash_map(data->cracked_map, hex_hash, password, algs[j], exists->index);
                pthread_rwlock_unlock(&hash_map_rwlock);

                // pthread_mutex_unlock(&hash_map_lock);
            }
            // else{
            //     fprintf(fp, "not found\n");
            // }
            // pthread_mutex_unlock(&file_mutex); 

            free(hash);
        }
    }

    // fclose(fp);

    return NULL;
}


// Function name: crack_hashed_passwords
// Description:   Computes different hashes for each password in the password list,
//                then compare them to the hashed passwords to decide whether if
//                any of them matches this password. When multiple passwords match
//                the same hash, only the first one in the list is printed.
void crack_hashed_passwords(char *password_list, char *hashed_list, char *output) {
    // hash_map *map = create_hash_map();
    hash_map *cracked_map = create_hash_map();
    FILE *fp;
    char password[256];  // passwords have at most 255 characters
    char hex_hash[2 * KEEP + 1]; // hashed passwords have at most 'keep' characters

        // Load hashed passwords
        int n_hashed = 0;
        struct cracked_hash_details *cracked_hashes;
        fp = fopen(hashed_list, "r");
        assert(fp != NULL);
        while (fscanf(fp, "%s", hex_hash) == 1)
            n_hashed++;
        rewind(fp);
        cracked_hashes = (struct cracked_hash_details *)malloc(n_hashed * sizeof(struct cracked_hash_details));
        assert(cracked_hashes != NULL);
        for (int i = 0; i < n_hashed; i++) {
            char curr_hash[2 * KEEP + 1];
            fscanf(fp, "%s", cracked_hashes[i].hash);
            // fscanf(fp, "%s", curr_hash);
            // cracked_hashes[i].hash = strdup(curr_hash);
            // printf("fscanf done\n");
            // insert_hash_map(cracked_map, curr_hash, NULL, NULL, i);
            insert_hash_map(cracked_map, cracked_hashes[i].hash, NULL, NULL, i);
            // printf("insert done\n");
            cracked_hashes[i].password = NULL;
            cracked_hashes[i].alg = NULL;
        }
        fclose(fp);

    // Read all passwords into an array once
    int n_passwords = 0;
    char **passwords = NULL;

    fp = fopen(password_list, "r");
    assert(fp != NULL);
    while (fgets(password, sizeof(password), fp)) {
        if (password[0] != '\n' && password[0] != '\0') {
            passwords = realloc(passwords, (n_passwords + 1) * sizeof(char *));
            passwords[n_passwords] = strdup(password);
            passwords[n_passwords][strcspn(passwords[n_passwords], "\n")] = '\0'; // Remove newline
            n_passwords++;
        }
    }
    fclose(fp);

    // Prepare multithreading
    int num_threads = 8;
    pthread_t threads[num_threads];
    thread_data thread_data_array[num_threads];
    int passwords_per_thread = n_passwords / num_threads;

    for (int i = 0; i < num_threads; i++) {
        // thread_data_array[i].map = map;
        thread_data_array[i].cracked_map = cracked_map;
        thread_data_array[i].cracked_hashes = cracked_hashes;
        thread_data_array[i].passwords = passwords;
        thread_data_array[i].start_index = i * passwords_per_thread;
        thread_data_array[i].end_index = (i == num_threads - 1) ? n_passwords : (i + 1) * passwords_per_thread;
        pthread_create(&threads[i], NULL, crack_passwords_thread, &thread_data_array[i]);
    }

    // Wait for all threads
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
        // // Match cracked hashes
        // for (int j = 0; j < n_hashed; j++) {
        //     if (cracked_hashes[j].password != NULL) {
        //         continue;
        //     }
        //     cracked_hash *result = get_hash_map(map, cracked_hashes[j].hash);
        //     if (result) {
        //         cracked_hashes[j].password = strdup(result->password);
        //         cracked_hashes[j].alg = result->alg;
        //     }
        // }
    
        // // Print results
        fp = fopen(output, "w");
        assert(fp != NULL);
        for (int i = 0; i < n_hashed; i++) {
            if (cracked_hashes[i].password == NULL)
                fprintf(fp, "not found\n");
            else
                fprintf(fp, "%s:%s\n", cracked_hashes[i].password, cracked_hashes[i].alg);
        }
        fclose(fp);

    // Free allocated memory
    for (int i = 0; i < n_passwords; i++) {
        free(passwords[i]);
    }
    free(passwords);

    // free_hash_map(map);
    free_hash_map(cracked_map);
}


// Hash function (djb2 algorithm)
unsigned long hash_function(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash % HASH_SIZE;
}

// Create a new hash map
hash_map* create_hash_map() {
    hash_map *map = malloc(sizeof(hash_map));
    if (!map) {
        perror("Failed to allocate hash map");
        exit(EXIT_FAILURE);
    }
    map->buckets = calloc(HASH_SIZE, sizeof(hash_node *));
    if (!map->buckets) {
        perror("Failed to allocate hash map buckets");
        free(map);
        exit(EXIT_FAILURE);
    }
    return map;
}

// Insert into hash map
void insert_hash_map(hash_map *map, const char *key, const char *password, const char *alg, int index) {
    unsigned long index_ = hash_function(key);
    hash_node *new_node = malloc(sizeof(hash_node));
    if (!new_node) {
        perror("Failed to allocate node");
        exit(EXIT_FAILURE);
    }

    strncpy(new_node->key, key, 2 * KEEP);
    new_node->key[2 * KEEP] = '\0';

    new_node->value.index = index;

    if (password == NULL){
        new_node->value.password = NULL;
    }
    else{
        new_node->value.password = strdup(password);
    }
    if (alg == NULL){
        new_node->value.alg = NULL;
    }
    else{
        new_node->value.alg = strdup(alg);
    }
    new_node->next = map->buckets[index_];
    map->buckets[index_] = new_node;
}

// void insert_hash_map(hash_map *map, const char *key, const char *password, const char *alg) {
//     unsigned long index = hash_function(key);
//     hash_node *current = map->buckets[index];

//     while (current) {
//         if (strcmp(current->key, key) == 0) {
//             // If key exists but has NULL values, update it
//             if (current->value.password == NULL) {
//                 current->value.password = strdup(password);
//                 current->value.alg = strdup(alg);
//             }
//             return;  // Prevent duplicate inserts
//         }
//         current = current->next;
//     }

//     // If key does not exist, insert a new node
//     hash_node *new_node = malloc(sizeof(hash_node));
//     if (!new_node) {
//         perror("Failed to allocate node");
//         exit(EXIT_FAILURE);
//     }

//     strncpy(new_node->key, key, 2 * KEEP);
//     new_node->key[2 * KEEP] = '\0';

//     new_node->value.password = strdup(password);
//     new_node->value.alg = strdup(alg);
//     new_node->next = map->buckets[index];
//     map->buckets[index] = new_node;
// }

// Retrieve from hash map
cracked_hash* get_hash_map(hash_map *map, const char *key) {
    unsigned long index = hash_function(key);
    hash_node *node = map->buckets[index];
    while (node) {
        if (strcmp(node->key, key) == 0) {
            return &node->value;
        }
        node = node->next;
    }
    return NULL;
}

// Delete from hash map
void delete_hash_map(hash_map *map, const char *key) {
    unsigned long index_ = hash_function(key);
    hash_node *node = map->buckets[index_];
    hash_node *prev = NULL;

    while (node) {
        if (strcmp(node->key, key) == 0) {
            if (prev) {
                prev->next = node->next;
            } else {
                map->buckets[index_] = node->next;
            }
            free(node->value.password);
            free(node->value.alg);
            // free(node->value.index);
            free(node);
            return;
        }
        prev = node;
        node = node->next;
    }
}

// Free hash map
void free_hash_map(hash_map *map) {
    for (int i = 0; i < HASH_SIZE; i++) {
        hash_node *node = map->buckets[i];
        while (node) {
            hash_node *temp = node;
            node = node->next;
            free(temp->value.password);
            free(temp->value.alg);
            // free(node->value.index);
            free(temp);
        }
    }
    free(map->buckets);
    free(map);
}
