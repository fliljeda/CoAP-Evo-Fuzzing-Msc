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
#include "coap_mutations.cpp"
#include "server_handler.cpp"
#include "fuzzer.cpp"
#include "logger.cpp"
#include "evo_handler.cpp"

vector<mutation_target> targs = {
    VERSION,
    TYPE,
    TOKEN_LENGTH,
    CODE_CLASS,
    CODE_DETAIL,
    MSG_ID,
    TOKEN,
    OPTION,
    PAYLOAD,
};
vector<mutation_rule> rules ={
    STR_EMPTY,
    STR_PREDEFINED,
    STR_ADD_NON_PRINTABLE,
    STR_OVERFLOW,
    UINT_EMPTY,
    UINT_ABSOLUTE_MINUS_ONE,
    UINT_ABSOLUTE_ONE,
    UINT_ABSOLUTE_ZERO,
    UINT_ADD_ONE,
    UINT_SUBTRACT_ONE,
    UINT_MAX_RANGE,
    UINT_MIN_RANGE,
    UINT_MAX_RANGE_PLUS_ONE,
    OPAQUE_EMPTY,
    OPAQUE_PREDEFINED,
    OPAQUE_OVERFLOW,
    EMPTY_PREDEFINED,
    EMPTY_ABSOLUTE_MINUS_ONE,
    EMPTY_ABSOLUTE_ONE,
    EMPTY_ABSOLUTE_ZERO,
    PAYLOAD_EMPTY,
    PAYLOAD_PREDEFINED,
    PAYLOAD_ADD_NON_PRINTABLE,
    BITFLIP
};

void printPacket(std::vector<std::byte>& bytes){
    for(size_t j = 0; j < bytes.size(); j++){
        printf("%02X ", (unsigned int)bytes[j]);
        if(j > 32){
            printf("...");
            break;
        }
    }
    cout << "\n";
}
void printPacket(coap_packet& cpack){
    std::vector<std::byte> bytes = packPacket(cpack);
    printPacket(bytes);
}

void printDiff(coap_packet& cpack1, coap_packet& cpack2){
    std::vector<std::byte> bytes1,bytes2;
    bytes1 = packPacket(cpack1);
    bytes2 = packPacket(cpack2);
    //printPacket(cpack1);
    //printPacket(cpack2);
    size_t max = bytes1.size() > bytes2.size() ? bytes2.size() : bytes1.size();
    for(size_t i = 0; i < max; i++){
        if(bytes1[i] != bytes2[i]){
            std::byte b = bytes1[i] ^ bytes2[i];
            printf("(%02X) ", (unsigned int) b);
        }else{
            printf("%02X ", (unsigned int)bytes1[i]);
        }
        if(i > 35){
            printf("...");
            break;
        }
    }
    printf("\n");
}

int testCodeCoverage(){
    std::vector<coap_packet> packets = readPacketFile("./seed.txt");
    startRecPoolCoverage();
    int cc = getSessionCodeCoverage(packets);

    cout << "Code Coverage 1: " << cc << "\n";
    int poolCC = endRecPoolCoverage();
    cout << "Pool Code Coverage: " << poolCC << "\n";
    return poolCC;
}


int testMutations(){
    coap_packet cpack = readPacketFile("./seed.txt", 1)[0];
    coap_packet tmp;
    //cpack = mutate(cpack, PAYLOAD, PAYLOAD_PREDEFINED);
    printPacket(cpack);
    
    //mutation_target randTarg = targs[rand()%targs.size()];
    //cout << "randTarg: " << randTarg << "\n";
    //tmp = mutate(cpack, randTarg, BITFLIP);
    //printPacket(tmp);
    for(size_t j = 0; j < rules.size(); j++){
        std::cout << "Target: " << OPTION << " Rule: " << rules[j] << "\n";
        tmp = cpack;
        mutate_option(tmp.options[1], rules[j]);
        printDiff(cpack,tmp);
    }
    return 0;
}


int testHarmfulPackets(){
    auto harmful =  get_logged_packets("190412-102931");
    std::string s;
    std::cout << "Log: ";
    std::cin >> s;
     
    for(auto& y: harmful){
        std::cout << "confirm send next packet:";
        std::cin >> s;
        std::cout << y.size() << "\n";
        sendPacket(y);
    }
    return 0;
}


int main(int argc, char *argv[]){
    std::srand(std::time(nullptr) ^ getpid());
    if(argc == 2){
        readConfig(argv[1]);
    }else{
        readConfig();
    }
    getSeedFilePackets();
    //testHarmfulPackets();
    //return 0;
    
    evo_run();
    /*     TEST EVO            */

    
    return 0;
    /* ************************** */

    auto pool = generatePool(10, 10);
    startRecPoolCoverage();
    for(size_t i = 0; i < pool.size(); i++){
        int n = getSessionCodeCoverage(pool[i]);
        std::cout << "Session Fitness: " << n << "\n";
    }

    int n = endRecPoolCoverage();
    std::cout << "Pool Fitness: " << n << "\n";
    
   return 0;
}
