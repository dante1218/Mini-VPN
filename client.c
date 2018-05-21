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
#include <netinet/in.h>
#include <fcntl.h>
#include <termios.h>

#define BUFF_SIZE 2000
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "ca_client"
struct sockaddr_in peerAddr;
struct addrinfo hints, *result;
int PORT_NUMBER = 55555;
const char *hostname;
//this function is used to hide the password which typed by the user
int getch() {
     struct termios oldtc;
     struct termios newtc;
     int ch;
     tcgetattr(STDIN_FILENO, &oldtc);
     newtc = oldtc;
     newtc.c_lflag &= ~(ICANON | ECHO);
     tcsetattr(STDIN_FILENO, TCSANOW, &newtc);
     ch=getchar();
     tcsetattr(STDIN_FILENO, TCSANOW, &oldtc);
     return ch;
}

//initialize a tun device
int createTunDevice() {
     int tunfd;
     struct ifreq ifr;
     memset(&ifr, 0, sizeof(ifr));
     ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
     tunfd = open("/dev/net/tun", O_RDWR);
     ioctl(tunfd, TUNSETIFF, &ifr);
     return tunfd;
}

//initialize ssl parameter
SSL* setupTLSClient(const char* hostname, SSL_CTX* ctx)
{
     // Step 0: OpenSSL library initialization
     // This step is no longer needed as of version 1.1.0.
     SSL_library_init();
     SSL_load_error_strings();
     SSLeay_add_ssl_algorithms();
     SSL_METHOD *meth;
     SSL* ssl;
     meth = (SSL_METHOD *)TLSv1_2_method();
     ctx = SSL_CTX_new(meth);
     //this line is used to set the verification flag
     //so when the client connect to the server, a callback function will be called
     //to check the certificate, this function can be set by programmer
     //if there is no special callback function, then the default ctx callback function will be used
     SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
     //Telling the client program where are CA's certificates
     //which are used to verify server's certificate
     if(SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1){
         printf("Error setting the verify locations. \n");
         exit(0);
    }
     //create an SSL data structure, which will be used for making a TLS connection
     ssl = SSL_new (ctx);
     //these two lien is used to check the hostname typed by the user
     //matches the common name on the server's certificate or not
     X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
     X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);
     return ssl;
}

int connectToTCPServer(const char *hostname){
     //get host IP address from hostname
     hints.ai_family = AF_INET;
     int error = getaddrinfo(hostname, NULL, &hints, &result);
     if (error) {
         fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
         exit(1);
     }
     struct sockaddr_in* ip = (struct sockaddr_in *) result->ai_addr;
     // Create a TCP socket
     int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
     //fill in destination infromation
     memset(&peerAddr, 0, sizeof(peerAddr));
     peerAddr.sin_family = AF_INET;
     peerAddr.sin_port = htons(PORT_NUMBER);
     peerAddr.sin_addr.s_addr = inet_addr((char *)inet_ntoa(ip->sin_addr));
     //connect to the destination
     connect(sockfd, (struct sockaddr*) &peerAddr,
     sizeof(peerAddr));
     return sockfd;
}

void tunSelected(int tunfd, int sockfd, SSL *ssl){
     int len;
     char buff[BUFF_SIZE];
     bzero(buff, BUFF_SIZE);
     len = read(tunfd, buff, BUFF_SIZE);
     //encrypt and send packet by SSL_write
     SSL_write (ssl, buff, sizeof(buff)-1);
}
void socketSelected (int tunfd, int sockfd, SSL *ssl){
     int len;
     char buff[BUFF_SIZE];
     bzero(buff, BUFF_SIZE);
     //receive and decrypt by SSL_read
     int err = SSL_read (ssl, buff, sizeof(buff)-1);
     buff[err] = '\0';
     write(tunfd, buff, err);
}

void startVPN (int sockfd, SSL* ssl) {
     int tunfd = createTunDevice();
     //monitor transfer packets between two file descriptors (one for TUN,
     //one for socket) by using system call select()
     while (1) {
         fd_set readFDSet;
         //using FD_SET to store monitored file descriptors in a set
         FD_ZERO(&readFDSet);
         FD_SET(sockfd, &readFDSet);
         FD_SET(tunfd, &readFDSet);
         //given the set to select()
        //this function will block the process until data are available on one
        //of the file descriptors
         select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
         //FD_ISSER is used to know which file descriptor has received data
         if (FD_ISSET(tunfd, &readFDSet)) tunSelected(tunfd, sockfd, ssl);
         if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd, ssl);
     }
}

int main (int argc, char * argv[]) {
     const char *hostname;
     SSL_CTX *ctx;
     int tunfd, sockfd;
     if (argc > 1) hostname = argv[1];
     else {
         printf("Please enter a legal host name.\n");
         return 0;
     }
     if (argc > 2) PORT_NUMBER = atoi(argv[2]);
     //TLS initialization
     SSL *ssl = setupTLSClient(hostname, ctx);
     //create a TCP conncetion
     sockfd = connectToTCPServer(hostname);
     //TLS handshake
     char readbuf[2000];
     SSL_set_fd(ssl, sockfd);
     int err = SSL_connect(ssl); CHK_SSL(err);
     printf("SSL connection is successful\n");
     printf ("SSL connection using %s\n", SSL_get_cipher(ssl));
     err = SSL_write (ssl, "Connect to Server!", strlen("Connect to Server!"));
     err = SSL_read (ssl, readbuf, sizeof(readbuf)-1);
     readbuf[err] = '\0';
     printf("receive: %s\n", readbuf);
     //user verification
     char username[20];
     char password[20];
     char check[50];
     err = SSL_read (ssl, readbuf, sizeof(readbuf)-1);
     readbuf[err] = '\0';
     printf("%s\n", readbuf);
     scanf("%s", username);
     err = SSL_write (ssl, username, sizeof(username));
     err = SSL_read (ssl, readbuf, sizeof(readbuf)-1);
     readbuf[err] = '\0';
     printf("%s\n", readbuf);

     //hide user password
     int ch, i = 0;
     ch = getch();
     for(;;){
         ch = getch();
         if(ch == '\n') {
             password[i] = '\0';
             break;
         }
         else {
             password[i] = (char)ch;
             i++;
         }
     }
     err = SSL_write (ssl, password, sizeof(password));
     err = SSL_read (ssl, readbuf, sizeof(readbuf)-1);
     readbuf[err] = '\0';
     strncpy(check, readbuf, sizeof(readbuf));
     //if the credential typed by user is not correct
     //the server will send "bad" to client
     //and the connection will be closed
     //otherwise, the connection will established
     if (strcmp(check, "bad") == 0){
         printf("Verification failed, disconnected!\n");
         close(sockfd);
         SSL_shutdown(ssl);
         SSL_free(ssl);
         exit(0);
     }
     else {
        printf("Verification passed! Your tun IP address is %s\n", check);
     }
     //TCP connection and TLS session are established
     //strat the VPN
     startVPN(sockfd, ssl);
     close(sockfd);
     SSL_shutdown(ssl);
     SSL_free(ssl);
}
