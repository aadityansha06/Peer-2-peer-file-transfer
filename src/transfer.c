#include "lib/header.h"
#include "lib/ui.h"
#include "lib/integrity.h"
#include "lib/path_utils.h"
#include "lib/progressbar.h"
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <arpa/inet.h>

#define Reciver_port 9090
#define BUF_SIZE (16 * 1024) // 16kb page size

typedef struct
{
    char file_name[100];
    uint64_t file_size;
} fileinfo;

void sender(const char* target_ip, const char* input_path);
void reciver();

mode_t original_permissions;
typedef enum
{
    HEADER1_FAIL, 
    RESPONSE1_OK,   
    RESPONSE1_FAIL, 
    TRANSFER_SUCCESS = 100,
    TRANSFER_FAIL = 400,
} response;

int check_dir_permission(char dir_path[PATH_MAX])
{
    struct stat sb;
    if (stat(dir_path, &sb) != 0)
    {
        perror("stat");
        return 1;
    }
    original_permissions = sb.st_mode;
    if (!(sb.st_mode & S_IWUSR))
    {
        printf("%sWrite permission missing. Temporarily enabling...%s\n", GB_YELLOW, RESET);
        if (chmod(dir_path, sb.st_mode | S_IWUSR) != 0)
        {
            perror("Failed to change permissions");
            return -1;
        }
    }
    return 1;
}

void restore_dir_permission(char dir_path[PATH_MAX])
{
    if (chmod(dir_path, original_permissions) == 0)
    {
        printf("%sOriginal directory permissions restored.%s\n", GB_GREEN, RESET);
    }
    else
    {
        perror("Failed to restore permissions");
    }
}

#ifndef BUILDING_GUI
int main()
{
    int opt = 2;
    system("clear");
    printf(RESET "\n");
    printf(GB_AQUA "Peer-2-Peer" GB_GRAY "• " GB_GREEN "File-Transfer" GB_GRAY "• " GB_YELLOW "Simple " GB_GRAY "• " GB_PURPLE "Powerful" GB_ORANGE "                 ║\n");

    printf("\n1. File sender ");
    printf("\n2. File reciver - \n" GB_AQUA "(reciver must start theri programme first) \n" GB_ORANGE);
    printf("\n3.  Press 0 for exit ");

    if (scanf("%d", &opt) != 1) return EXIT_FAILURE;

    while (opt != 0)
    {
        switch (opt)
        {
        case 1: {
            char ip[INET_ADDRSTRLEN];
            char path[PATH_MAX];
            printf("%s\n enter the reciver's ip address \t%s", GB_BLUE, RESET);
            scanf("%s", ip);
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF);
            printf("%s\n Enter the file path :  %s", GB_YELLOW, RESET);
            if (fgets(path, PATH_MAX, stdin) != NULL) {
                size_t len = strlen(path);
                if (len > 0 && path[len-1] == '\n') path[len-1] = '\0';
            }
            sender(ip, path);
            break;
        }
        case 2:
            reciver();
            break;
        default:
            printf("%s\n please enter a valid choice or press 0 for exit%s", GB_RED, RESET);
            if (scanf("%d", &opt) != 1) opt = 0;
            break;
        }
        if (opt != 0) {
            printf("\n1. File sender\n2. File reciver\n0. Exit\nChoice: ");
            if (scanf("%d", &opt) != 1) opt = 0;
        }
    }
    printf(RESET "\n");
    return EXIT_SUCCESS;
}
#endif

void sender(const char* target_ip, const char* input_path)
{
    char file_path[PATH_MAX];
    fileinfo info;
    
    strncpy(file_path, input_path, PATH_MAX - 1);
    file_path[PATH_MAX - 1] = '\0';

    size_t len = strlen(file_path);
    while (len > 0 && isspace((unsigned char)file_path[len - 1])) {
        file_path[--len] = '\0';
    }
    char *start = file_path;
    while (*start && isspace((unsigned char)*start)) start++;
    if (start != file_path) {
        memmove(file_path, start, strlen(start) + 1);
        len = strlen(file_path);
    }
    if (len >= 2 && ((file_path[0] == '\'' && file_path[len - 1] == '\'') || 
                     (file_path[0] == '"' && file_path[len - 1] == '"'))) {
        memmove(file_path, file_path + 1, len - 2);
        file_path[len - 2] = '\0';
    }

    FILE *fp = fopen(file_path, "rb");
    if (fp == NULL)
    {
        fprintf(stderr, "%sError opening the file: %s%s\n", GB_RED, file_path, RESET);
        return;
    }

    fseek(fp, 0L, SEEK_END);
    info.file_size = ftell(fp);
    rewind(fp);

    struct sockaddr_in dest_addr;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        fprintf(stderr, "%sError creating socket%s\n", GB_RED, RESET);
        fclose(fp);
        return;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(Reciver_port);
    if (inet_pton(AF_INET, target_ip, &dest_addr.sin_addr) <= 0) {
        fprintf(stderr, "%sInvalid IP address: %s%s\n", GB_RED, target_ip, RESET);
        fclose(fp);
        close(sockfd);
        return;
    }

    printf("%sConnecting to %s:%d...%s\n", GB_YELLOW, target_ip, Reciver_port, RESET);
    if (connect(sockfd, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr)) < 0)
    {
        perror("Connection failed");
        fclose(fp);
        close(sockfd);
        return;
    }
    printf("%sConnected to receiver.%s\n", GB_GREEN, RESET);

    const char *filename = get_filename(file_path);
    strncpy(info.file_name, filename, sizeof(info.file_name) - 1);
    info.file_name[sizeof(info.file_name) - 1] = '\0';
    sanitize_filename(info.file_name);

    uint8_t file_hash[SHA256_DIGEST_SIZE];
    if (sha256_file(file_path, file_hash) != 0)
    {
        fprintf(stderr, "%sError hashing file%s\n", GB_RED, RESET);
        fclose(fp);
        close(sockfd);
        return;
    }
    char hash_hex[SHA256_DIGEST_SIZE * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++)
        sprintf(hash_hex + (i * 2), "%02x", file_hash[i]);

    char header[2056];
    snprintf(header, sizeof(header), "File_Name:%s\nFile_Size:%llu\nFile_Hash:%s\n", info.file_name, (unsigned long long)info.file_size, hash_hex);
    if (send(sockfd, header, strlen(header) + 1, 0) < 0) {
        perror("Failed to send header");
        fclose(fp);
        close(sockfd);
        return;
    }

    char response_buf[2056];
    int n = recv(sockfd, response_buf, sizeof(response_buf) - 1, 0);
    if (n <= 0)
    {
        fprintf(stderr, "%sError receiving response or connection closed%s\n", GB_RED, RESET);
        fclose(fp);
        close(sockfd);
        return;
    }
    response_buf[n] = '\0';
    int code = -1;
    sscanf(response_buf, "Buffer-status-%d", &code);

    if (code == RESPONSE1_OK)
    {
        printf("%sReceiver ready, sending file...%s\n", GB_GREEN, RESET);
        char buffer[BUF_SIZE];
        size_t read_n;
        uint64_t total_sent = 0;
        while ((read_n = fread(buffer, 1, BUF_SIZE, fp)) > 0)
        {
            ssize_t sent = 0;
            while (sent < (ssize_t)read_n)
            {
                ssize_t s = send(sockfd, buffer + sent, read_n - sent, 0);
                if (s <= 0)
                {
                    perror("send error");
                    goto cleanup;
                }
                sent += s;
            }
            total_sent += sent;
            progressbar(total_sent, info.file_size);
        }
        printf("\n");
        printf("%sData sent successfully. Waiting for confirmation...%s\n", GB_AQUA, RESET);
        
        char final_response[100];
        int m = recv(sockfd, final_response, sizeof(final_response) - 1, 0);
        if (m > 0) {
            final_response[m] = '\0';
            sscanf(final_response, "File-transfer:%d", &code);
            if (code == TRANSFER_SUCCESS) printf("%sReceiver confirmed transfer success!%s\n", GB_GREEN, RESET);
            else printf("%sReceiver reported transfer failure.%s\n", GB_RED, RESET);
        }
    } else {
        printf("%sReceiver rejected buffer creation.%s\n", GB_RED, RESET);
    }

cleanup:
    fclose(fp);
    close(sockfd);
}

void reciver()
{
    response response_code;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("Socket failed"); return; }

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(Reciver_port);

    if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) { 
        perror("Bind failed"); 
        close(sockfd); 
        return; 
    }
    if (listen(sockfd, 10) < 0) { 
        perror("Listen failed"); 
        close(sockfd); 
        return; 
    }

    printf("%sReceiver is listening on port %d...%s\n", GB_AQUA, Reciver_port, RESET);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int clientfd = accept(sockfd, (struct sockaddr *)&client_addr, &addr_len);
        if (clientfd < 0) { 
            perror("Accept failed"); 
            continue; 
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        printf("%sAccepted connection from %s%s\n", GB_GREEN, client_ip, RESET);

        char recived_header[2056];
        int n = recv(clientfd, recived_header, sizeof(recived_header) - 1, 0);
        if (n <= 0) { 
            fprintf(stderr, "%sError receiving header%s\n", GB_RED, RESET); 
            close(clientfd); 
            continue; 
        }
        recived_header[n] = '\0';

        char file_name[100];
        uint64_t file_size;
        char received_hash_hex[65];
        unsigned long long temp_size;
        if (sscanf(recived_header, "File_Name:%s\nFile_Size:%llu\nFile_Hash:%s\n", file_name, &temp_size, received_hash_hex) < 2) {
            fprintf(stderr, "%sInvalid header format%s\n", GB_RED, RESET);
            close(clientfd);
            continue;
        }
        file_size = (uint64_t)temp_size;

        char response_buf[100];
        response_code = RESPONSE1_OK;
        snprintf(response_buf, sizeof(response_buf), "Buffer-status-%d", response_code);
        send(clientfd, response_buf, strlen(response_buf) + 1, 0);

        char dir_path[PATH_MAX];
        if (getcwd(dir_path, PATH_MAX) != NULL) {
            check_dir_permission(dir_path);
        }

        FILE *fp = fopen(file_name, "wb");
        if (fp == NULL) { 
            fprintf(stderr, "%sError opening file for writing: %s%s\n", GB_RED, file_name, RESET); 
            close(clientfd); 
            continue; 
        }

        printf("%sReceiving file: %s (%llu bytes)%s\n", GB_GREEN, file_name, (unsigned long long)file_size, RESET);
        char buffer[BUF_SIZE];
        uint64_t recive_bytes = 0;
        while (recive_bytes < file_size)
        {
            n = recv(clientfd, buffer, BUF_SIZE, 0);
            if (n <= 0) break;
            
            size_t written = fwrite(buffer, 1, n, fp);
            recive_bytes += written;
            progressbar(recive_bytes, file_size);
        }
        printf("\n");
        fclose(fp);

        if (recive_bytes == file_size)
        {
            uint8_t calculated_hash[SHA256_DIGEST_SIZE];
            sha256_file(file_name, calculated_hash);
            char calculated_hash_hex[SHA256_DIGEST_SIZE * 2 + 1];
            for (int i = 0; i < SHA256_DIGEST_SIZE; i++) sprintf(calculated_hash_hex + (i * 2), "%02x", calculated_hash[i]);

            if (strcmp(received_hash_hex, calculated_hash_hex) == 0) {
                printf("%sIntegrity Verified: Hash Matches%s\n", GB_GREEN, RESET);
                response_code = TRANSFER_SUCCESS;
            } else {
                printf("%sIntegrity Check FAILED: Hash Mismatch!%s\n", GB_RED, RESET);
                response_code = TRANSFER_FAIL;
            }
        } else {
            printf("%sTransfer incomplete: %llu / %llu bytes received%s\n", GB_RED, (unsigned long long)recive_bytes, (unsigned long long)file_size, RESET);
            response_code = TRANSFER_FAIL;
        }

        char final_response_header[100];
        snprintf(final_response_header, sizeof(final_response_header), "File-transfer:%d", response_code);
        send(clientfd, final_response_header, strlen(final_response_header) + 1, 0);
        
        restore_dir_permission(dir_path);
        close(clientfd);
        printf("%sReceiver finished handling file.%s\n", GB_GREEN, RESET);
    }
    close(sockfd);
}