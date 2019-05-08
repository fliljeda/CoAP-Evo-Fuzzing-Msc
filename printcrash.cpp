#include "logger.cpp"
#include "network_handler.cpp"
#include <vector>
#include <experimental/filesystem>
using std::string;
namespace fsys = std::experimental::filesystem;

int sendCrashPack(string log, string dir = "crashlogs"){
    //log = "190415-134443";
    //dir = "crashlogs";
    auto packs = get_logged_packets(log, dir);
    string str;
    for(auto& pack: packs){
        netw::coap_socket s = netw::getCoapSocket("127.0.0.1");
        s.sendUDP(pack);
        s.recUDP(1);
        s.close_socket();
        std::cout << "Waiting: ";
        std::cin >> str;
    }
    return 0;
}

void printLog(string log){
    auto packs = get_logged_packets(log);
    for(auto& pack: packs){
        
        if(pack.size() > 50){
            std::cout << "Big packet: " << pack.size() << ": \n";
        }
        for(auto& b: pack){
            if((unsigned int)b == 0xb0){
                printf("(%02X) ", (unsigned int)b);
            }else{
                printf("%02X ", (unsigned int)b);
            }
        }
        std::cout << "\n";
    }
}

int main(int argc, char* argv[]){
    string dir = "crashlogs";
    bool send = 0;
    if(argc > 1){
        if(string(argv[1]).compare("send") == 0){
            send = 1;
            if(argc > 2){
                if(argc > 3){
                    sendCrashPack(string(argv[2]), string(argv[3]));
                }else{
                    sendCrashPack(string(argv[2]));
                }
                return 0;
            }
        }else{
            printLog(argv[1]);
            return 0;
        }
    }
    for(fsys::directory_entry p: fsys::directory_iterator(dir)){
        string s;
        std::cout << "-----------------------\n";
        string filename = p.path().filename();
        std::cout << filename << ":\n";
        auto packs = get_logged_packets(filename);
        if(send){
            for(auto& pack: packs){
                netw::coap_socket s = netw::getCoapSocket("127.0.0.1");
                s.sendUDP(pack);
                s.recUDP(1);
                s.close_socket();
            }
            std::cout << "#################################################\n";
            std::cin >> s;
            continue;
        }
        for(auto& pack: packs){
            
            if(pack.size() > 50){
                std::cout << "Big packet: " << pack.size() << ": ";
                for(auto& b: pack){
                    if((unsigned int) b == 0xb0){
                        std::cout << "Found famous 0xb0\n";
                        break;
                    }
                    if((unsigned int) b == 0xFF){
                        break;
                    }
                }
                std::cout << "\n";
                continue;
            }
            for(auto& b: pack){
                if((unsigned int)b == 0xb0){
                    printf("(%02X) ", (unsigned int)b);
                }else{
                    printf("%02X ", (unsigned int)b);
                }
            }
            std::cout << "\n";
        }
    }
    return 0;
}
