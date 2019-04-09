#include <fstream>
#include <vector>
#include <cstddef>
#include <iostream>
#include <string>
#include <experimental/filesystem>

#ifndef COAP_LOGGER
#define COAP_LOGGER

using std::string;
namespace fsys = std::experimental::filesystem;

/* Returns a Y-m-d string of now */
string getClockString(){
        std::time_t now_c = time(nullptr);
        char time[20];
        strftime(time, sizeof(time), "%y%m%d%H%M%S", localtime(&now_c));
        return string(time);
}


std::vector<std::vector<std::byte>> get_logged_packets(string logName, string dirName = "crashlogs"){
    std::ostringstream s;
    s << dirName << "/" << logName;
    string path = s.str();
    std::vector<std::vector<std::byte>> packets;
    
    std::ifstream fs(path);
    string tmp;
    while(getline(fs,tmp)){
        size_t size = stoi(tmp);
        std::vector<std::byte> pack;
        char c;
        for(size_t i = 0; i < size; i++){
            fs.get(c);
            pack.push_back(std::byte(c));
        }
        fs.get(c); //newline
        packets.push_back(pack);
    }

    return packets;
}

string log_packets(std::vector<std::vector<std::byte>>& packs){
    string dirName = "crashlogs";
    if(!fsys::exists(dirName)){
        std::cout << dirName << " directory does not exist. Creating it..." << "\n";
        int res = fsys::create_directory(dirName);
        if(res){
            std::cout << "Created directory: " << dirName << "\n";
        }else{
            std::cout << "Failed to create directory: " << dirName << "\n";
            std::cout << "Returning.." << "\n";
            return "";
        }
    }
    string logName =  getClockString();
    std::ostringstream s;
    s << dirName << "/" << logName;
    string path = s.str();
    
    while(fsys::exists(path)){
        s << "X";
        path = s.str();
    }

    string contents;

    for(size_t i = 0; i < packs.size(); i++){
        std::vector<std::byte> packet_bytes = packs[i];
        // Add size of next line
        contents.append(std::to_string(packet_bytes.size())).append("\n");
        for(size_t j = 0; j < packet_bytes.size(); j++){
            unsigned char c = (unsigned char)(unsigned int)packet_bytes[j];
            contents.push_back(c);
        }
        contents.push_back('\n');
    }

    std::ofstream ofs(path);
    ofs << contents;

    std::cout << logName << "\n";
    return logName;
}

#endif
