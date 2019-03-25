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

void* getRawFromVec(std::vector<std::byte> vec){
    return 0;
}

int sendUDP(std::string host, std::vector<std::byte> data){
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
    
    if (sendto(s, &data[0], data.size(), 0, (sockaddr*)&si_other, slen)==-1)
        diep("sendto()");

    char buf[BUFLEN];
    if (recvfrom(s, buf, BUFLEN, 0, (sockaddr*)&si_other, (socklen_t*)&slen)==-1)
        diep("recvfrom()");
    printf("Received packet from %s:%d\nData: %s\n\n",
        inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port), buf);

    close(s);
    return 0;
}


}
