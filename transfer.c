#include <stddef.h>
#define _GNU_SOURCE 
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <libgen.h> // Required for basename()
#include <inttypes.h>
// defining a macro to use POSIX function 

#define Reciver_port 9090
#define BUF_SIZE (16 * 1024) // 16kb page size 
char reciver_ip_addr[INET_ADDRSTRLEN]; // INET_ADDRSTRLEN is atleast 16 digit 

typedef struct {
 char file_name[100];
    uint64_t file_size; // total file size in bytes to be sent 
   // unsigned *char file_buffer; // file buffer in bytes

}fileinfo;

void sender();
void reciver();

typedef  enum{
    HEADER1_FAIL, // 0 filed reieving or ceating header 1 

    RESPONSE1_OK, // 1 
    RESPONSE1_FAIL,//2 
    TRANSFER_SUCCESS=100,
    TRANSFER_FAIL=400,
}response;

int main(){
    int opt=2;
    printf("peer-2-peer File Transfer \n Pls enter your choice ");
    printf("\n1. File sender \n");
    printf("\n File reciver - (reciver must start theri programme first) \n");
    scanf("%d",&opt);
    
    while (opt!=0) {
        switch (opt) {
            case 1:
                sender();
                break;
            case 2:
                reciver();
                break;
            default:
                printf("\n please enter a valid choice");
            break;
        }
    
    }

    return EXIT_SUCCESS;
}


void sender(){
    char file_path[500];
    fileinfo info;
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    printf("\n enter the reciver's ip address \t");
    scanf("%s",reciver_ip_addr);
    printf("\n Enter the file path :  ");
    scanf("%s",file_path);
    
    FILE *fp;
    fp = fopen(file_path,"rb");
    
    if (fp==NULL) {
    fprintf(stderr,"Error opening the file");
        return;
    
    }
    
        //Move the file pointer to the end of the file
    fseek(fp, 0L, SEEK_END);

    // Get the  file size ofr uint64_t
    info.file_size = ftell(fp);
rewind(fp); // jumping on the start of file 
  //  Extract the integer descriptor for the read() function
int fd = fileno(fp);

        struct sockaddr_in dest_addr;

    int sockfd = socket(AF_INET,SOCK_STREAM,0);
    if (sockfd<0) {

              fprintf(stderr,"Error creating socket");
        //free(byte_buffer);

        EXIT_SUCCESS;
     


    
    }
    
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(Reciver_port);
    dest_addr.sin_addr.s_addr = inet_addr(reciver_ip_addr);
    
    
    if( connect(sockfd,(struct sockaddr*)&dest_addr, sizeof(struct sockaddr))<0){
        perror("connection failed");
        //free(byte_buffer);

        EXIT_FAILURE;

    }
    printf("Connected to recvier.\n");
      // Create a mutable copy of the file_path
  char *filename = strrchr(file_path, '/');
    if (filename == NULL) {
   strncpy(info.file_name, file_path, sizeof(info.file_name) - 1);// No slash found, the whole string is the filename
} else {
    strncpy(info.file_name, filename + 1, sizeof(info.file_name) - 1); // Move past the '/' to get filename
}
    

// sending file_name and total size to the reciver as header 

   // strncpy(info.file_name, filename, sizeof(info.file_name) - 1);
info.file_name[sizeof(info.file_name) - 1] = '\0'; // Safety null terminator
  


    char header[2056];

   snprintf(header, sizeof(header), "File_Name:%s\nFile_Size:%" PRIu64 "\n", info.file_name, info.file_size);


    send(sockfd,header, strlen(header) + 1, 0); // +1 for null
     

        char response_1[2056];
    int n = recv(sockfd, response_1, sizeof(response_1) - 1, 0);
        
        if (n < 0) {
            perror("Error reciving the header");
         //   free(byte_buffer);

            EXIT_FAILURE;
    }
    int code= -1;
    sscanf(response_1,"Buffer-status-%d",&code);
      
    if (code==RESPONSE1_OK) {
        printf("Buffer created sucessfully \n sending file...\n");
          char buffer[BUF_SIZE];
        ssize_t n;
        // sending 16kb at once 
while ((n = fread(buffer, 1, BUF_SIZE, fp))>0) {
   ssize_t sent = 0;
    while (sent < n) {
        ssize_t s = send(sockfd, buffer + sent, n - sent, 0);
        if (s <= 0) {
            perror("send");
            EXIT_FAILURE;
        }
        sent += s;
    }
        
}
   
  
        

        // data sent sucessfully ? checking whether reciver has wrote it or not 
                printf("Data sent sucessfully\n waiting for recvier confirmation ...");
            char final_response[100];
                     int m = recv(sockfd, final_response, sizeof(final_response) - 1, 0);
        
        if (m < 0) {
            perror("Error reciving the final_response");
    //        free(byte_buffer);

            EXIT_FAILURE;
    }
    
    sscanf(final_response,"File-transfer:%d",&code);
            if (code==TRANSFER_SUCCESS) {
                printf("\nReciver has recived the entire file\n");
  //              free(byte_buffer);
                close(sockfd);
                EXIT_SUCCESS;
            
            }else if (code==TRANSFER_FAIL) {
                         

                     printf("\nOPPS!.. reciver unbale to recive the entire file \n");
 //               free(byte_buffer);
                close(sockfd);
                EXIT_SUCCESS;
            

            }

        
    }

        
   

    
 fclose(fp);

//    free(byte_buffer);
    close(sockfd);
}




void reciver(){
       response response_code;
    printf("Provide your IP to the sender\n");
      system("hostname -I");
    int    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { 
        perror("Socket failed"); 
        EXIT_FAILURE; 
    }

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        EXIT_FAILURE;
    }

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(Reciver_port);

    if (bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("Bind failed");
        EXIT_FAILURE;
    }

    if (listen(sockfd, 10) < 0) {
        perror("Listen failed");
         EXIT_FAILURE;
    }
     struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int clientfd = accept(sockfd, (struct sockaddr *)&client_addr, &len);

        if (clientfd < 0) {
            perror("Accept failed");
            EXIT_FAILURE;
        }
      char recived_header1[2056];
     int n = recv(clientfd, recived_header1, sizeof(recived_header1) - 1, 0);
        
        if (n < 0) {
            perror("Error reciving the header");
            EXIT_FAILURE;
    }
    char file_name[100];
    uint64_t file_size; // total file size
    sscanf(recived_header1, "File_Name:%s\nFile_Size:%" PRIu64 "\n",file_name,&file_size);
   //   unsigned char* byte_buffer= (unsigned char*)malloc(file_size);
        // a buffer size of memroy has been created 
    /*if (byte_buffer==NULL) {
             fprintf(stderr,"Error opening the file");
          char HEADER_FAIL[100];
       response_code = HEADER1_FAIL;
   snprintf(HEADER_FAIL, sizeof(HEADER_FAIL), "Buffer-status-%d",response_code);


    send(clientfd,HEADER_FAIL, strlen(HEADER_FAIL) + 1, 0); // +1 for null


        EXIT_FAILURE;
     
    }*/ 
    
     char responseOK[100];
       response_code = RESPONSE1_OK;
   snprintf(responseOK, sizeof(responseOK), "Buffer-status-%d",response_code);
    ssize_t recive_bytes = 0;


    send(clientfd,responseOK, strlen(responseOK) + 1, 0); // +1 for null

       system("chmod 777 ."); 
    FILE *fp = fopen(file_name,"wb");
    if (fp==NULL) {
        printf("Error opening writing file\n");
        return;
    }
    //rewind(fp);
    printf("file created sucessfully \n");
    int fd = fileno(fp);
   char buffer[BUF_SIZE]; 
    printf("wait data is being written \n");
    while (recive_bytes<file_size) {
    
    
        n = recv(clientfd, buffer, BUF_SIZE, 0);
        if (n <= 0) {
            printf("unable to recive data\n");
            return;
        }
        ssize_t written_bytes =0;
    while (written_bytes < n) {
        ssize_t w  = fwrite(buffer, 1, n, fp);
        if (w <= (size_t )n) {
            perror("write");
            EXIT_FAILURE;
        }
        written_bytes += w;
    
    
    }
    
recive_bytes += written_bytes;
    printf("\rProgress: %" PRIu64 "/%" PRIu64 " bytes", recive_bytes, file_size);
    fflush(stdout);

    }

printf( "\nfinish reciving data" );

    if (recive_bytes==file_size) {
        response_code=TRANSFER_SUCCESS;
        char final_response_header[2056];
    snprintf(final_response_header,sizeof(final_response_header),"File-transfer:%d",response_code);
        send(clientfd,final_response_header, strlen(final_response_header) + 1, 0); 
        fclose(fp);
        close(sockfd);
    
    }else {
        response_code=TRANSFER_FAIL;
        char final_response_header[2056];
    snprintf(final_response_header,sizeof(final_response_header),"File-transfer:%d",response_code);
         send(clientfd,final_response_header, strlen(final_response_header) + 1, 0); 

        fclose(fp);
        close(sockfd);
        
    }


    }
