#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <shadow.h>
#include <crypt.h>
#include <stdlib.h>
#include "myheader.h"
#define PORT_NUMBER 55555
#define BUFF_SIZE 2000
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
struct sockaddr_in peerAddr;
//Once the server started, it will allocate a range of IP address for following client
void allocateIP(char **childPipe, char *base, int increment, int pipNum)
{
     char *new_str;
     for(int i=0; i<pipNum; i++){
         int length = snprintf( NULL, 0, "%d", increment );
         char* convert = malloc( length + 1 );
         snprintf( convert, length + 1, "%d", increment );
         if((new_str = malloc(strlen(base)+strlen(convert)+1)) != NULL){
             new_str[0] = '\0'; // ensures the memory is an empty string
             strcat(new_str,base);
             strcat(new_str,convert);
         }
         //map the child i to current IP address
         childPipe[i] = new_str;
         //increment the IP address
         increment = increment+1;
     }
     return;
}

//compare the username and password which sent by the client
//with the credential in the shadow file
//if they match, return 1 else return -1
int login(char *user, char *passwd)
{
     struct spwd *pw;
     char *epasswd;
     pw = getspnam(user);
     if (pw == NULL) {
        return -1;
     }
     epasswd = crypt(passwd, pw->sp_pwdp);
     if (strcmp(epasswd, pw->sp_pwdp)) {
        return -1;
     }
     return 1;
}

int createTunDevice() {
     int tunfd;
     struct ifreq ifr;
     memset(&ifr, 0, sizeof(ifr));

     ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

     tunfd = open("/dev/net/tun", O_RDWR);
     ioctl(tunfd, TUNSETIFF, &ifr);

     return tunfd;
}

int initTCPServer() {
     struct sockaddr_in sa_server;
     int listen_sock;

     listen_sock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
     CHK_ERR(listen_sock, "socket");
     memset(&sa_server, 0, sizeof(sa_server));
     sa_server.sin_family = AF_INET;
     sa_server.sin_addr.s_addr = htonl(INADDR_ANY);
     sa_server.sin_port = htons(PORT_NUMBER);

     int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
     CHK_ERR(err, "bind");
     err = listen(listen_sock, 5);
     CHK_ERR(err, "listen");

     return listen_sock;
}

void socketSelected (int tunfd, int sockfd, SSL *ssl){
     int len;
     char buff[BUFF_SIZE];

     //printf("Got a packet from the tunnel\n");

     bzero(buff, BUFF_SIZE);
     int err = SSL_read (ssl, buff, sizeof(buff)-1);
     buff[err] = '\0';
     write(tunfd, buff, err);
}
//child processes use this function to receive packet from parent
void parentSelected (int parentPipe, int sockfd, SSL *ssl){
     int len;
     char buff[BUFF_SIZE];
     //read packet from pipe
     len = read(parentPipe, buff, sizeof(buff)-1);
     //send packet out by correct tunnel
     SSL_write (ssl, buff, sizeof(buff)-1);
}

void startVPN (int tunfd, int sockfd, SSL* ssl, int parentPipe) {
    while (1) {
         fd_set readFDSet;

         FD_ZERO(&readFDSet);
         FD_SET(sockfd, &readFDSet);
         FD_SET(tunfd, &readFDSet);
         FD_SET(parentPipe, &readFDSet);
         select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

         if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd, ssl);
         if (FD_ISSET(parentPipe, &readFDSet)) parentSelected(parentPipe, sockfd, ssl);
    }
}

int main (int argc, char * argv[]) {

     //initialize TLS
     char readbuf[2000];
     char readbuf2[2000];
     SSL_METHOD *meth;
     SSL_CTX* ctx;
     SSL *ssl;
     int err;
     int sockfd;
     int pipNum = 10;//number of child process, we will have. This number can be changed
     char *childPipe[pipNum];//create a table, which will map every child process to different tun IP address
     char *base = "192.168.53.";//base IP address of TUN
     int increment = 10;//the tun IP address will start from 192.168.53.10
     //allocating a range IP address and pipe for following client
     allocateIP(childPipe, base, increment, pipNum);

     // Step 0: OpenSSL library initialization
     SSL_library_init();
     SSL_load_error_strings();
     SSLeay_add_ssl_algorithms();

     // Step 1: SSL context initialization
     meth = (SSL_METHOD *)TLSv1_2_method();
     ctx = SSL_CTX_new(meth);
     SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
     // Step 2: Set up the server certificate and private key
     SSL_CTX_use_certificate_file(ctx, "lu-cert.pem", SSL_FILETYPE_PEM);
     SSL_CTX_use_PrivateKey_file(ctx, "lu-key-dec.pem", SSL_FILETYPE_PEM);
     // Step 3: Create a new SSL structure for a connection
     ssl = SSL_new (ctx);

     //setup TCP socket, waiting for connection
     struct sockaddr_in sa_client;
     size_t client_len;
     int listen_sock = initTCPServer();
     //create tun interface
     int tunfd = createTunDevice();
     //allocate pipe for each child processes
     int count = 0;
     int fd[2*pipNum];
     pid_t pid;
     //initialize all pipes
     for(int i = 0; i < pipNum; i++){
        pipe(&fd[2*i]);
     }
     
     while(1){
         //after fork child processes, parent keeps to check tun interface to see if there is any packet
         //if there is packet from private network, the parent will forward it to correct child process
         while(count == pipNum){
             int len = 0;
             char buff[BUFF_SIZE];

             //parent got packet from tun
             bzero(buff, BUFF_SIZE);
             len = read(tunfd, buff, BUFF_SIZE);
             //get the head of the packet and check it IP address fields
             struct ipheader* ip = (struct ipheader*)buff;
             int ip_header_len = ip->iph_ihl*4; // compute IP header length
             //comparing the destination IP with each tunnel IP
             //and forwarding the packet to corresponding child process
             for(int i=0; i<pipNum;i++){
                 if(strcmp(inet_ntoa(ip->iph_destip), childPipe[i]) == 0){
                 write(fd[2*i+1], buff, sizeof(buff));
                 }
             }
         }

         //fork child processes
         if((pid = fork()) == -1) {
             perror("fork");
             exit(1);
         }
         if(pid>0) { //parent proces
            close(fd[count*2]); // Close the input end of the pipe.
         }
         else { //child process
             close(fd[count*2+1]); // Close the output end of the pipe.
             int parentPipe = fd[count*2]; //get current child pipe
             int childID = count; //get current child ID
             while(1){
                 //child processes take the responsibility to accept following client
                 sockfd = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);
                 //TCP socket is ready, setup TLS section
                 SSL_set_fd (ssl, sockfd);
                 err = SSL_accept (ssl);
                 CHK_SSL(err);
                 printf ("SSL connection established!\n");
                 err = SSL_read (ssl, readbuf, sizeof(readbuf)-1);
                 readbuf[err] = '\0';
                 printf("receive: %s\n", readbuf);
                 err = SSL_write (ssl, "Connection established!", strlen("Connection established!"));

                 //client verification
                 err = SSL_write (ssl, "Please enter username:", strlen("Please enter username:"));
                 err = SSL_read (ssl, readbuf, sizeof(readbuf)-1);
                 readbuf[err] = '\0';

                 err = SSL_write (ssl, "Please enter password:", strlen("Please enter password:"));
                 err = SSL_read (ssl, readbuf2, sizeof(readbuf)-1);
                 readbuf2[err] = '\0';

                 //if the user does not provide correct credentials
                 //then the connection will be terminated
                 if(login(readbuf, readbuf2) == 1){
                     printf("user verification pass!\n");
                     err = SSL_write (ssl, childPipe[childID], sizeof("xxx.xxx.xxx.xxx"));
                     //credential are correct, so start VPN
                     startVPN(tunfd, sockfd, ssl, parentPipe);
                 }
                 else {
                     printf("wrong username or password, disconnected!\n");
                     err = SSL_write (ssl, "bad", sizeof("bad"));
                     close(sockfd);
                     SSL_shutdown(ssl);
                     SSL_free(ssl);
                 }

                 close(sockfd);
                 SSL_shutdown(ssl);
                 SSL_free(ssl);
             }
         }
         count++;
     }

}
