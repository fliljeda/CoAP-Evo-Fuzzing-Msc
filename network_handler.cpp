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

#ifndef COAP_NETWORK_HANDLER
#define COAP_NETWORK_HANDLER

#define PORT 5683
#define BUFLEN 512
#define SRV_IP "127.0.0.1"

namespace netw{

void diep(std::string s){
    perror(s.c_str());
    exit(1);
}



struct coap_socket{

    int socket;
    sockaddr_in si_other;
    int slen;
    coap_socket& close_socket(){
        close(socket);
        return *this;
    }

    //Receive from socket
    /*  TODO Return something to identify crashes and whatnot  */
    bool recUDP(int timeout_sec = 0, long timeout_usec = 0L){

        //Set timeout
        struct timeval tv;
        tv.tv_sec = timeout_sec;
        tv.tv_usec = timeout_usec;
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        char buf[BUFLEN];

        if (recvfrom(socket, buf, BUFLEN, 0, (sockaddr*)&(si_other), (socklen_t*)&(slen))==-1){
            //std::cout << "Got no response from the CoAP server\n";
            return 0;
        }else{
            //printf("Received packet from %s:%d\nData: %s\n\n",inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port), buf);
            printf("Received packet data: %s\n", buf);
            return 1;
        }

    }

    /* Send the given param2 data over the param1 given socket */
    coap_socket& sendUDP(const std::vector<std::byte>& data){
        std::cout << "Sending:\n";
        if (sendto(socket, &data[0], data.size(), 0, (sockaddr*)&(si_other), slen)==-1){
            std::cout << "Could not send packet\n";
        }

        return *this;
    }

};


void closeSocket(coap_socket s){
    close(s.socket);
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


}

#endif
