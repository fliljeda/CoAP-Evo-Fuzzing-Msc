#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <regex>
#include <sys/wait.h>
#include <experimental/filesystem>
#include <vector>
#include <cstddef>
#include "network_handler.cpp"
#include "packet_handler.cpp"
#include "mutations.cpp"
#include "server_handler.cpp"

int main(int argc, char *argv[]){
    if(argc == 2){
        readConfig(argv[1]);
    }else{
        readConfig();
    }


    std::vector<coap_packet> packets = readPacketFile("./seed.txt");
    std::vector<coap_packet> packets1, packets2, packets3, packets4;
    packets1.push_back(packets[0]);
    packets2.push_back(packets[1]);
    packets3.push_back(packets[4]);
    packets4.push_back(packets[5]);
    startRecPoolCoverage();
    int cc = getSessionCodeCoverage(packets1);
    int cc2 = getSessionCodeCoverage(packets2);
    int cc3 = getSessionCodeCoverage(packets3);
    int cc4 = getSessionCodeCoverage(packets4);

    cout << "Code Coverage 1: " << cc << "\n";
    cout << "Code Coverage 2: " << cc2 << "\n";
    cout << "Code Coverage 3: " << cc3 << "\n";
    cout << "Code Coverage 4: " << cc4 << "\n";
    int poolCC = endRecPoolCoverage();
    cout << "Pool Code Coverage: " << poolCC << "\n";
    return 0;
}
