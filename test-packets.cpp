
#include "logger.cpp"
#include "network_handler.cpp"
#include <vector>
#include <experimental/filesystem>
using std::string;
using std::cout;
using std::cin;
using std::vector;
namespace fsys = std::experimental::filesystem;

int firstX(int num, std::vector<std::byte>& targ, std::vector<std::byte>& src){
    targ.clear();
    for(int i = 0; i < num; i++){
        targ.push_back(src[i]);
    }
    return 0;
}
int dissectPacket(std::vector<std::byte>& pack){
    std::vector<std::byte> tmp;
    string s;
    int i = 1;
    while(size_t(i) < pack.size()){
        firstX(i++, tmp, pack);
        for(auto& b: tmp){
            printf("%02X ", (unsigned int)b);
        }
        cout << "send?\n";
        cin >> s;
        if(s.size() > 1){
        }

        netw::coap_socket s = netw::getCoapSocket("127.0.0.1");
        s.sendUDP(tmp);
        bool success = s.recUDP(2);
        if(!success){
            dissectPacket(pack);
            cout << "Did not respond\n";
        }
        s.close_socket();
    }
    return 0;
}

int main(int argc, char* argv[]){
    string inpFile = "";
    for(int i = 1; i < argc; i++){
        string arg_curr = string(argv[i]);
        if(arg_curr[0] == '-'){
            //Flag
            if(++i >= argc){
                std::cout << "Exiting\n";
                return 0;
            }
            string flag = arg_curr;
            arg_curr = string(argv[i]);
            if(flag.compare("-f") == 0){
                inpFile = arg_curr;
            }
        }
    }

    auto packs = get_logged_packets(inpFile);
    int packet_n = 0;
    for(auto& pack: packs){
        netw::coap_socket s = netw::getCoapSocket("127.0.0.1");
        s.sendUDP(pack);
        bool success = s.recUDP(2);
        if(!success){
            dissectPacket(pack);
            cout << "Did not respond\n";
        }
        packet_n++;
        s.close_socket();
    }
    std::cout << "Exiting normally\n";
    return 0;
}
