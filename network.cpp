#include <iostream>
#include <vector>
#include <cstddef>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>

#define PORT 5683
#define BUFLEN 512
#define SRV_IP "127.0.0.1"

namespace netw{

void diep(std::string s){
    perror(s.c_str());
    exit(1);
}


template<typename T>
struct coap_header_field{
    int assertion = T();
    int length;
    T val;
};

struct coap_socket{
    int socket;
    sockaddr_in si_other;
    int slen;
};

void closeSocket(coap_socket s){
    close(s.socket);
}


//Receive from socket
void recUDP(coap_socket& s, int timeout_sec = 0, long timeout_usec = 0){

    //Set timeout
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0L;
    setsockopt(s.socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char buf[BUFLEN];

    if (recvfrom(s.socket, buf, BUFLEN, 0, (sockaddr*)&(s.si_other), (socklen_t*)&(s.slen))==-1)
        diep("recvfrom()");
    printf("Received packet from %s:%d\nData: %s\n\n",
        inet_ntoa(s.si_other.sin_addr), ntohs(s.si_other.sin_port), buf);

}

/* Creates a socket to send coap packets over
 * with the given address */
coap_socket getCoapSocket(std::string host){
    struct sockaddr_in si_other;
    int s, slen=sizeof(si_other);
    
    if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
      diep("socket");
    
    std::memset((char *) &si_other, 0, sizeof(si_other));
    si_other.sin_family = AF_INET;
    si_other.sin_port = htons(PORT);
    if (inet_aton(SRV_IP, &si_other.sin_addr)==0) {
      fprintf(stderr, "inet_aton() failed\n");
      exit(1);
    }

    coap_socket sock = {s, si_other, slen};
    return sock;
}


/* Send the given param2 data over the param1 given socket */
coap_socket sendUDP(coap_socket& s, const std::vector<std::byte>& data){
    if (sendto(s.socket, &data[0], data.size(), 0, (sockaddr*)&(s.si_other), s.slen)==-1)
        diep("sendto()");

    return s;
}


}
