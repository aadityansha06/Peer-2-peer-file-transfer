#include "lib/header.h"
#include "lib/ui.h"
#include "lib/integrity.h"
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define Reciver_port 9090
#define BUF_SIZE (16 * 1024) // 16kb page size

char reciver_ip_addr[INET_ADDRSTRLEN]; // INET_ADDRSTRLEN is atleast 16 digit

typedef struct
{
    char file_name[100];
    uint64_t file_size; // total file size in bytes to be sent
                        // unsigned *char file_buffer; // file buffer in bytes

} fileinfo;

void sender();
void reciver();
mode_t original_permissions;
typedef enum
{
    HEADER1_FAIL, // 0 filed reieving or ceating header 1

    RESPONSE1_OK,   // 1
    RESPONSE1_FAIL, // 2
    TRANSFER_SUCCESS = 100,
    TRANSFER_FAIL = 400,
} response;
int check_dir_permission(char dir_path[PATH_MAX])
{
    // using stat() to get the dir  info
    struct stat sb;
    if (stat(dir_path, &sb) != 0)
    {
        perror("stat");
        return 1;
    }
    // Store the permissions in a mode_t variable
    original_permissions = sb.st_mode;
    if (!(sb.st_mode & S_IWUSR))
    { // if wirte permission is missing
        printf("Write permission missing. Temporarily enabling...\n");

        // Add User Write permission to existing bits
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
        printf("\nOriginal directory permissions restored.\n");
    }
    else
    {
        perror("Failed to restore permissions");
    }
}
int main()
{
    int opt = 2;
    system("clear");
    printf(RESET "\n");
    printf(GB_AQUA "Peer-2-Peer" GB_GRAY "• " GB_GREEN "File-Transfer" GB_GRAY "• " GB_YELLOW "Simple " GB_GRAY "• " GB_PURPLE "Powerful" GB_ORANGE "                 ║\n");

    printf("\n1. File sender ");
    printf("\n2. File reciver - \n" GB_AQUA "(reciver must start theri programme first) \n" GB_ORANGE);
    printf("\n3.  Press 0 for exit ");

    scanf("%d", &opt);

    while (opt != 0)
    {
        switch (opt)
        {

        case 1:
            sender();
            break;
        case 2:
            reciver();
            break;
        default:
            printf(GB_RED "\n please enter a valid choice or press 0 for exit" RESET);
            scanf("%d", &opt);
            break;
        }
    }
    printf(RESET "\n");
    return EXIT_SUCCESS;
}

void sender()
{
    char file_path[PATH_MAX];
    fileinfo info;
    int c;
    while ((c = getchar()) != '\n' && c != EOF)
        ;
    printf(GB_BLUE "\n enter the reciver's ip address \t");
    scanf("%s", reciver_ip_addr);
    printf(GB_YELLOW "\n Enter the file path :  ");
    scanf("%s", file_path);

    FILE *fp;
    fp = fopen(file_path, "rb");

    if (fp == NULL)
    {
        fprintf(stderr, GB_RED "Error opening the file");
        return;
    }

    // Move the file pointer to the end of the file
    fseek(fp, 0L, SEEK_END);

    // Get the  file size ofr uint64_t
    info.file_size = ftell(fp);
    rewind(fp); // jumping on the start of file

    struct sockaddr_in dest_addr;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {

        fprintf(stderr, GB_RED "Error creating socket");
        // free(byte_buffer);

        EXIT_SUCCESS;
    }

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(Reciver_port);
    dest_addr.sin_addr.s_addr = inet_addr(reciver_ip_addr);

    if (connect(sockfd, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr)) < 0)
    {
        perror(GB_RED "connection failed");

        EXIT_FAILURE;
    }
    printf(GB_GREEN "Connected to recvier.\n");
    // Create a mutable copy of the file_path
    char *filename = strrchr(file_path, '/');
    if (filename == NULL)
    {
        strncpy(info.file_name, file_path, sizeof(info.file_name) - 1); // No slash found, the whole string is the filename
    }
    else
    {
        strncpy(info.file_name, filename + 1, sizeof(info.file_name) - 1); // Move past the '/' to get filename
    }

    info.file_name[sizeof(info.file_name) - 1] = '\0'; // Safety null terminator

    uint8_t file_hash[SHA256_DIGEST_SIZE];
    if (sha256_file(file_path, file_hash) != 0)
    {
        fprintf(stderr, GB_RED "Error hashing file");
        fclose(fp);
        close(sockfd);
        return;
    }
    char hash_hex[SHA256_DIGEST_SIZE * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++)
        sprintf(hash_hex + (i * 2), "%02x", file_hash[i]);

    char header[2056];

    snprintf(header, sizeof(header), "File_Name:%s\nFile_Size:%" PRIu64 "\nFile_Hash:%s\n", info.file_name, info.file_size, hash_hex);

    send(sockfd, header, strlen(header) + 1, 0); // +1 for null

    char response_1[2056];
    int n = recv(sockfd, response_1, sizeof(response_1) - 1, 0);

    if (n < 0)
    {
        perror(GB_RED "Error reciving the header");

        EXIT_FAILURE;
    }
    int code = -1;
    sscanf(response_1, "Buffer-status-%d", &code);

    if (code == RESPONSE1_OK)
    {
        printf(GB_GREEN "Buffer created sucessfully \n sending file...\n" RESET);
        char buffer[BUF_SIZE];
        ssize_t n;
        // reading  16kb at once
        while ((n = fread(buffer, 1, BUF_SIZE, fp)) > 0)
        {
            ssize_t sent = 0;
            while (sent < n)
            {
                ssize_t s = send(sockfd, buffer + sent, n - sent, 0);
                if (s <= 0)
                {
                    perror("send");
                    EXIT_FAILURE;
                }
                sent += s;
            }
        }

        // data sent sucessfully ? checking whether reciver has wrote it or not
        printf(GB_AQUA "\nData sent sucessfully\n waiting for recvier confirmation ..." RESET);
        char final_response[100];
        int m = recv(sockfd, final_response, sizeof(final_response) - 1, 0);

        if (m < 0)
        {
            perror(GB_RED "\nError reciving the final_response");
            //

            EXIT_FAILURE;
        }

        sscanf(final_response, "File-transfer:%d", &code);
        if (code == TRANSFER_SUCCESS)
        {
            printf(GB_GREEN "\nReciver has recived the entire file\n" RESET);
            //
            close(sockfd);
            EXIT_SUCCESS;
        }
        else if (code == TRANSFER_FAIL)
        {

            printf(GB_BG_RED "\nOPPS!.. reciver unbale to recive the entire file \n");
            //
            close(sockfd);
            EXIT_SUCCESS;
        }
    }

    fclose(fp);

    close(sockfd);
}

void reciver()
{
    response response_code;
    printf(GB_AQUA "Provide your IP to the sender\n");
    system("hostname -I");
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("Socket failed");
        EXIT_FAILURE;
    }

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt failed");
        EXIT_FAILURE;
    }

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(Reciver_port);

    if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        perror("Bind failed");
        EXIT_FAILURE;
    }

    if (listen(sockfd, 10) < 0)
    {
        perror("Listen failed");
        EXIT_FAILURE;
    }
    struct sockaddr_in client_addr;
    socklen_t len = sizeof(client_addr);
    int clientfd = accept(sockfd, (struct sockaddr *)&client_addr, &len);

    if (clientfd < 0)
    {
        perror("Accept failed");
        EXIT_FAILURE;
    }
    char recived_header1[2056];
    int n = recv(clientfd, recived_header1, sizeof(recived_header1) - 1, 0);

    if (n < 0)
    {
        perror(GB_RED "Error reciving the header");
        EXIT_FAILURE;
    }
    char file_name[100];
    uint64_t file_size; // total file size
    char received_hash_hex[65]; // 64 chars + null
    sscanf(recived_header1, "File_Name:%s\nFile_Size:%" PRIu64 "\nFile_Hash:%s\n", file_name, &file_size, received_hash_hex);

    char responseOK[100];
    response_code = RESPONSE1_OK;
    snprintf(responseOK, sizeof(responseOK), "Buffer-status-%d", response_code);
    ssize_t recive_bytes = 0;

    send(clientfd, responseOK, strlen(responseOK) + 1, 0); // +1 for null
    char dir_path[PATH_MAX];                               // path of current dir
    getcwd(dir_path, PATH_MAX);                            // getting user's current working dir

    int permission = check_dir_permission(dir_path);
    if (permission != 1)
    {
        printf("writing permission denined in this directory");
        close(sockfd);
        EXIT_SUCCESS;
    }
    FILE *fp = fopen(file_name, "wb");
    if (fp == NULL)
    {
        printf(GB_RED "Error opening writing file\n");
        return;
    }

    printf(GB_GREEN "file created sucessfully \n" RESET);
    char buffer[BUF_SIZE];
    printf(GB_YELLOW "wait data is being written \n");
    while (recive_bytes < file_size)
    {

        n = recv(clientfd, buffer, BUF_SIZE, 0);
        if (n <= 0)
        {
            printf(GB_RED "unable to recive data\n");
            return;
        }
        ssize_t written_bytes = 0;
        while (written_bytes < n)
        {
            ssize_t w = fwrite(buffer, 1, n, fp);
            if (w <= (size_t)n)
            {
                perror("write");
                EXIT_FAILURE;
            }
            written_bytes += w;
        }

        recive_bytes += written_bytes;
        printf(GB_BLUE BOLD "\n\rProgress: %" PRIu64 "/%" PRIu64 " bytes" RESET, recive_bytes, file_size);
        fflush(stdout);
    }

    if (recive_bytes == file_size)
    {
        fclose(fp);

        uint8_t calculated_hash[SHA256_DIGEST_SIZE];
        sha256_file(file_name, calculated_hash);

        char calculated_hash_hex[SHA256_DIGEST_SIZE * 2 + 1];
        for (int i = 0; i < SHA256_DIGEST_SIZE; i++)
            sprintf(calculated_hash_hex + (i * 2), "%02x", calculated_hash[i]);

        if (strcmp(received_hash_hex, calculated_hash_hex) == 0)
        {
            printf(GB_GREEN "\nIntegrity Verified: Hash Matches\n" RESET);
            response_code = TRANSFER_SUCCESS;
        }
        else
        {
            printf(GB_RED "\nIntegrity Check FAILED: Hash Mismatch!\n" RESET);
            printf("Expected: %s\nActual:   %s\n", received_hash_hex, calculated_hash_hex);
            response_code = TRANSFER_FAIL;
        }

        char final_response_header[2056];
        snprintf(final_response_header, sizeof(final_response_header), "File-transfer:%d", response_code);
        send(clientfd, final_response_header, strlen(final_response_header) + 1, 0);
        close(sockfd);
    }
    else
    {
        response_code = TRANSFER_FAIL;
        char final_response_header[2056];
        snprintf(final_response_header, sizeof(final_response_header), "File-transfer:%d", response_code);
        send(clientfd, final_response_header, strlen(final_response_header) + 1, 0);
        restore_dir_permission(dir_path);
        fclose(fp);
        close(sockfd);
    }
    int any;
    printf(GB_GREEN "\nfinish reciving data" RESET);
    restore_dir_permission(dir_path);
    printf(GB_PURPLE "\npress any number to back to the menu " RESET);
    scanf("%d", &any);
    EXIT_SUCCESS;
}
