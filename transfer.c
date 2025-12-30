#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <libgen.h> // Required for basename()
#include <inttypes.h>
#define _GNU_SOURCE // defining a macro to use POSIX function 

#define Reciver_port 9090

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
    printf("\n enter the reciver's ip address \t");
    scanf("%s",reciver_ip_addr);
    printf("\n Enter the file path :  ");
    scanf("%s",file_path);
    
    FILE *fp;
    fp = fopen(file_path,"r");
    
    if (fp==NULL) {
    fprintf(stderr,"Error opening the file");
        return;
    
    }
    char ch;
    int i =0;
        //Move the file pointer to the end of the file
    fseek(fp, 0L, SEEK_END);

    // Get the  file size ofr uint64_t
    info.file_size = ftell(fp);
    char buffer[2056];
while ((ch=fgetc(fp))!=EOF) {
   buffer[i]=ch;
        i++;
}
    fclose(fp);

     unsigned char* byte_buffer= (unsigned char*)malloc(info.file_size);
        // a buffer size of memroy has been created 
    if (byte_buffer==NULL) {
             fprintf(stderr,"Error opening the file");
        return;
     
    }
    // copying the string into that memory 
    //
    memcpy(byte_buffer,buffer,info.file_size);
  

        struct sockaddr_in dest_addr;

    int sockfd = socket(AF_INET,SOCK_STREAM,0);
    if (sockfd<0) {

              fprintf(stderr,"Error creating socket");
        free(byte_buffer);

        EXIT_SUCCESS;
     


    
    }
    
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(Reciver_port);
    dest_addr.sin_addr.s_addr = inet_addr(reciver_ip_addr);
    
    
    if( connect(sockfd,(struct sockaddr*)&dest_addr, sizeof(struct sockaddr))<0){
        perror("connection failed");
        free(byte_buffer);

        EXIT_FAILURE;

    }
    printf("Connected to server.\n");
      // Create a mutable copy of the file_path
  char   *filename=strchr(file_path,'/');
    if (filename == NULL) {
    filename = file_path; // No slash found, the whole string is the filename
} else {
    filename++; // Move past the '/' to get filename
}
    strcpy(filename,info.file_name);
  

    char header[2056];

   snprintf(header, sizeof(header), "File_Name:%s\nFile_Size:%" PRIu64 "\n", info.file_name, info.file_size);


    send(sockfd,header, strlen(header) + 1, 0); // +1 for null
     

        char response_1[2056];
    int n = recv(sockfd, response_1, sizeof(response_1) - 1, 0);
        
        if (n < 0) {
            perror("Error reciving the header");
            free(byte_buffer);

            EXIT_FAILURE;
    }
    int code= -1;
    sscanf(response_1,"Buffer-created:%d",&code);
      
    if (code==RESPONSE1_OK) {
        printf("Buffer created sucessfully \n sending file...\n");
       ssize_t size =  send(sockfd,header, strlen(header) + 1, 0); 
        if (size<0) {
            perror("Failed to send file data");
            free(byte_buffer);
        }else {
                printf("Data sent sucessfully\n waiting for recvier confirmation ...");
            char final_response[100];
                     int n = recv(sockfd, final_response, sizeof(final_response) - 1, 0);
        
        if (n < 0) {
            perror("Error reciving the final_response");
            free(byte_buffer);

            EXIT_FAILURE;
    }
    
    sscanf(final_response,"File-transfer:%d",&code);
            if (code==TRANSFER_SUCCESS) {
                printf("\nReciver has recived the entire file\n");
                free(byte_buffer);
                close(sockfd);
                EXIT_SUCCESS;
            
            }else if (code==TRANSFER_FAIL) {
                         

                     printf("\nOPPS!.. reciver unbale to recive the entire file \n");
                free(byte_buffer);
                close(sockfd);
                EXIT_SUCCESS;
            

            }

        }
    }

        
   

    

    free(byte_buffer);
    close(sockfd);
}




void reciver(){
       response response_code;

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
    uint64_t file_size;
    sscanf(recived_header1, "File_Name:%s\nFile_Size:%" PRIu64 "\n",file_name,&file_size);
      unsigned char* byte_buffer= (unsigned char*)malloc(file_size);
        // a buffer size of memroy has been created 
    if (byte_buffer==NULL) {
             fprintf(stderr,"Error opening the file");
          char HEADER_FAIL[100];
       response_code = HEADER1_FAIL;
   snprintf(HEADER_FAIL, sizeof(HEADER_FAIL), "Buffer-status-%d",response_code);


    send(clientfd,HEADER_FAIL, strlen(HEADER_FAIL) + 1, 0); // +1 for null


        EXIT_FAILURE;
     
    }
    
     char responseOK[100];
       response_code = RESPONSE1_OK;
   snprintf(responseOK, sizeof(responseOK), "Buffer-status-%d",response_code);


    send(clientfd,responseOK, strlen(responseOK) + 1, 0); // +1 for null

    

    

}
