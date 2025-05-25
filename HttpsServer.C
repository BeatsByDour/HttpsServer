#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <curl/curl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/sockios.h>

#define PORT 22
#define BUFFER_SIZE 4096
#define LOG_FILE "attack_logs.txt"
#define REVERSE_ATTACK_SIZE (100 * 1024 * 1024) // 100MB
#define GEO_API_URL "https://api.ipgeolocation.io/ipgeo"
#define GEO_API_KEY "YOUR_API_KEY" // Replace with your actual API key

// Structure to store response data from HTTP request
struct MemoryStruct {
    char *memory;
    size_t size;
};

// Callback function for CURL to write response data
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(!ptr) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

// Function to get geolocation data
char* get_geolocation(const char* ip) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory = malloc(1);
    chunk.size = 0;

    curl = curl_easy_init();
    if(curl) {
        char url[256];
        snprintf(url, sizeof(url), "%s?apiKey=%s&ip=%s&fields=country_name,city,latitude,longitude,isp,organization",
                GEO_API_URL, GEO_API_KEY, ip);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            free(chunk.memory);
            return NULL;
        }

        curl_easy_cleanup(curl);
    }

    return chunk.memory;
}

// Function to log attack information
void log_attack(const char* ip, int port, const char* data, const char* geo_info) {
    time_t now;
    time(&now);
    char* time_str = ctime(&now);
    time_str[strlen(time_str)-1] = '\0'; // Remove newline

    FILE* log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        return;
    }

    fprintf(log_file, "\n=== Attack Log ===\n");
    fprintf(log_file, "Time: %s\n", time_str);
    fprintf(log_file, "IP: %s\n", ip);
    fprintf(log_file, "Port: %d\n", port);
    
    if (data != NULL && strlen(data) > 0) {
        fprintf(log_file, "Data received (first 100 bytes): ");
        for (int i = 0; i < 100 && data[i] != '\0'; i++) {
            if (isprint(data[i])) {
                fprintf(log_file, "%c", data[i]);
            } else {
                fprintf(log_file, "\\x%02x", (unsigned char)data[i]);
            }
        }
        fprintf(log_file, "\n");
    }
    
    if (geo_info != NULL) {
        fprintf(log_file, "Geolocation Info:\n%s\n", geo_info);
    }

    fclose(log_file);
}

// Function to generate reverse attack data
void generate_reverse_attack_data(int sock) {
    char* buffer = malloc(REVERSE_ATTACK_SIZE);
    if (buffer == NULL) {
        perror("Failed to allocate memory for reverse attack");
        return;
    }

    // Fill buffer with data
    memset(buffer, 'X', REVERSE_ATTACK_SIZE);

    // Send data in chunks
    size_t total_sent = 0;
    while (total_sent < REVERSE_ATTACK_SIZE) {
        size_t to_send = (REVERSE_ATTACK_SIZE - total_sent) > BUFFER_SIZE ? BUFFER_SIZE : (REVERSE_ATTACK_SIZE - total_sent);
        ssize_t sent = send(sock, buffer + total_sent, to_send, 0);
        if (sent <= 0) {
            perror("Send failed during reverse attack");
            break;
        }
        total_sent += sent;
    }

    free(buffer);
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    // Initialize CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind socket to port 22
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Start listening
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("UnoReverse server listening on port %d...\n", PORT);

    while (1) {
        // Accept new connection
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            continue;
        }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &address.sin_addr, ip, INET_ADDRSTRLEN);
        int port = ntohs(address.sin_port);

        printf("New connection from %s:%d\n", ip, port);

        // Receive data from attacker
        ssize_t valread = read(new_socket, buffer, BUFFER_SIZE - 1);
        if (valread > 0) {
            buffer[valread] = '\0'; // Null-terminate the received data
        } else {
            strcpy(buffer, "[No data received]");
        }

        // Get geolocation information
        char* geo_info = get_geolocation(ip);

        // Log the attack
        log_attack(ip, port, buffer, geo_info);

        // Perform reverse attack
        printf("Performing reverse attack on %s:%d\n", ip, port);
        generate_reverse_attack_data(new_socket);
        printf("Reverse attack completed\n");

        // Clean up
        if (geo_info != NULL) {
            free(geo_info);
        }
        close(new_socket);
    }

    // Clean up CURL
    curl_global_cleanup();

    return 0;
}