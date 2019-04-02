#include <stdint.h>
#include <memory>
#include <vector>
#include <cstddef>
#include <iostream>
#include <fstream>

#ifndef COAP_PACKET_HANDLER
#define COAP_PACKET_HANDLER

std::vector<std::byte> strToByteVec(std::string& str);

template<typename T>
struct coap_field{
    T value;
    int bits;

    //Used for mutations
    int valid_min; //minimum valid value (length if string, opaque)
    int valid_max; //maximum valid value (length if string, opaque)

    void setVals(T val, int bits){
        this->value = val;
        this->bits = bits;
    }
    void print(){
        std::cout << "Bits: " << bits << " Valid Max/Min: "
            << valid_max << "/" << valid_min << "\n";
    }
};

struct coap_option{
    coap_field<int> number{0,4};
    coap_field<int> length{0,4};
    coap_field<int> optional_length{0,0};
    coap_field<int> optional_delta{0,0};
    enum Type {empty, opaque, uint, string};
    Type type;
    std::vector<std::byte> value;

    std::vector<std::byte>& getValue(){
        return value;
    }

    void setValue(unsigned int val, int bytes){
        std::vector<std::byte> vec;
        for(int i = 0; i < bytes; i++){
            unsigned int temp = (val >> (bytes-1-i)*8) & 255;
            vec.push_back(std::byte(temp));
        }
        value = vec;
    }
    void setValue(std::string val){
        value = strToByteVec(val);
    }

};

struct coap_packet{

    //Header
    coap_field<int> version{1,2,1,1};
    coap_field<int> type{1,2,0,4};
    coap_field<int> token_length{0,4,0,8};
    coap_field<int> code_class{0,3,0,7};
    coap_field<int> code_detail{0,5,0,31};
    coap_field<int> msg_id{0,16,0,0};

    //Token
    coap_field<int64_t> token{0,64,0,0};

    //Options
    std::vector<coap_option> options;

    //Payload
    bool write_payload_marker = 0;
    coap_field<int> payload_marker{0xFF,8};
    std::vector<std::byte> payload ;

};



std::vector<std::byte> strToByteVec(std::string& str){
    std::vector<std::byte> vec;
    for(unsigned char c: str){
        std::byte b{c};
        vec.push_back(b);
    }
    return vec;
}

/* Write param n_bits number of bits from param value  into vec
 * at the positiion param pos. Returns the new position
 * pos assumes position from left in the vector and the n_bits rightmost bits
 * is assumed for the value */
template<typename T>
int writeBits(std::vector<std::byte>& vec, T value, int pos, int n_bits){
    //std::cout << "writing: " << n_bits << " at pos "<< pos << "\n";
    size_t idx = pos/8;
    size_t offset = pos%8;
    //write null until we reach pos
    while(idx >= vec.size()){
        vec.push_back(std::byte(0));
    }

    //Write one bit at a time
    while(n_bits > 0){
        int shift = 7-offset;
        std::byte mask = std::byte(((value >> (n_bits-1)) & T(1)) << shift);

        vec[idx] = (vec[idx] & (~mask)) | mask;
        n_bits--;
        pos++;
        offset++;
        if(n_bits <= 0){
            break;
        }
        if(offset >= 8){
            vec.push_back(std::byte(0));
            idx++;
            offset = 0;
        }
    }

    return pos;
}

template<typename T>
int writeCoapField(std::vector<std::byte>& vec, coap_field<T>& field, int pos){
    return writeBits(vec, field.value, pos, field.bits);
}

/* Writes each vector element using the allocated sizes of the elements
 * Calculates the allocated sizes with sizeof*/ 
template<typename T>
int writeCoapVector(std::vector<std::byte>& vec, std::vector<T>& val, int pos){
    for(size_t i = 0; i < val.size(); i++){
        pos = writeBits(vec, val[i], pos, sizeof(val[i])*8);
    }
    return pos;
}

int writeCoapOptions(std::vector<std::byte>& vec, std::vector<coap_option>& options, int pos){
    int prevOptNum = 0;
    for(size_t i = 0; i < options.size(); i++){
        int delta = options[i].number.value - prevOptNum;
        int valLength = options[i].length.value;
        pos = writeBits(vec, delta, pos, options[i].number.bits);
        pos = writeCoapField(vec, options[i].length, pos);

        prevOptNum = options[i].number.value;
        if(delta == 13){
            pos = writeCoapField(vec, options[i].optional_delta, pos);
        }else if(delta == 14){
            pos = writeCoapField(vec, options[i].optional_delta, pos);
        }

        if(valLength == 13){
            pos = writeCoapField(vec, options[i].optional_length, pos);
            valLength += options[i].optional_length.value;
        }else if(valLength == 14){
            pos = writeCoapField(vec, options[i].optional_length, pos);
            valLength += options[i].optional_length.value;
        }

        switch (options[i].type){
            case coap_option::Type::empty:{
                //Write nothing
            }
            break;

            case coap_option::Type::opaque:{
                //cast to vector<byte>
                std::vector<std::byte> val = options[i].getValue();
                pos = writeCoapVector(vec, val, pos);
            }
            break;

            case coap_option::Type::uint:{
                //cast to unsigned int
                std::vector<std::byte> val = options[i].getValue();
                pos = writeCoapVector(vec, val, pos);
            }
            break;

            case coap_option::Type::string:{
                //case to string
                std::vector<std::byte> val = options[i].getValue();
                pos = writeCoapVector(vec, val, pos);
            }
            break;
        }
    }
    return pos;
}

int writeCoapPayload(std::vector<std::byte>& vec, coap_packet& pack, int pos){
    if(pack.payload.size() != 0 || pack.write_payload_marker){

        pos = writeCoapField(vec, pack.payload_marker, pos);
        pos = writeCoapVector(vec, pack.payload, pos);

    }
    return pos;
}


std::vector<std::byte> packPacket(coap_packet& pac){
    std::vector<std::byte> vec;
    int pos = 0;   
    pos = writeCoapField(vec, pac.version, pos);
    pos = writeCoapField(vec, pac.type, pos);
    pos = writeCoapField(vec, pac.token_length, pos);
    pos = writeCoapField(vec, pac.code_class, pos);
    pos = writeCoapField(vec, pac.code_detail, pos);
    pos = writeCoapField(vec, pac.msg_id, pos);
    pos = writeBits(vec, pac.token.value, pos, pac.token.value); //Token
    pos = writeCoapOptions(vec, pac.options, pos);
    pos = writeCoapPayload(vec, pac, pos);
    return vec;
}

std::vector<std::string> strSplit(std::string str, char delim){
    std::vector<std::string> vec;
    std::string tmp = "";
    for(size_t i = 0; i < str.size(); i++){
        if(str[i] == delim){
            while(i+1 < str.size() && str[i+1] == delim){
                i++;
            }
            vec.push_back(tmp);
            tmp = "";
            continue;
        }
        tmp.push_back(str[i]);
    }
    vec.push_back(tmp);
    return vec;
}

/* Sets the coap request code to the coap packet
 * Reads normal requests in capital letters GET, POST, PUT, DELETE*/
void setCoapCode(coap_packet& cpack, std::string val){
    if(val.compare("GET") == 0){
        cpack.code_class.setVals(0,3);
        cpack.code_detail.setVals(1,5);
    }else if(val.compare("POST") == 0){
        cpack.code_class.setVals(0,3);
        cpack.code_detail.setVals(2,5);
    }else if(val.compare("PUT") == 0){
        cpack.code_class.setVals(0,3);
        cpack.code_detail.setVals(3,5);
    }else if(val.compare("DELETE") == 0){
        cpack.code_class.setVals(0,3);
        cpack.code_detail.setVals(4,5);
    }
}

/* Sets the coap uri to the coap packet
 * Should not be prepended or appended with any slashes */
void setCoapUri(coap_packet& cpack, std::string uri){
    std::vector<std::string> comps = strSplit(uri, '/');
    for(std::string s: comps){
        coap_option opt;
        opt.number.setVals(0x0B, 4);
        if(s.size() > 268){
            opt.length.setVals(14, 4);
            opt.optional_length.setVals(s.size()-269, 16);
        }else if(s.size() > 12){
            opt.length.setVals(13, 4);
            opt.optional_length.setVals(s.size()-13, 8);
        }else{
            opt.length.setVals(s.size(), 4);
        }
        opt.value = strToByteVec(s);
        opt.type = coap_option::Type::string;
        cpack.options.push_back(opt);
    }
}


/* TODO if necessary add a type detector and handler  */
void setParsedCoapPayload(coap_packet& cpack, std::string type, std::string val){
    std::vector<std::byte> bytes = strToByteVec(val);
    cpack.payload = bytes;
    //std::vector<char> vec = std::vector<char>(val.begin(), val.end());
}
void setParsedCoapPayload(coap_packet& cpack, std::string val){
    setParsedCoapPayload(cpack, "bytes", val);
}

void setCoapDefaultVals(coap_packet& cpack){
    cpack.version.setVals(1,2);
    cpack.type.setVals(0,2);
    cpack.token_length.setVals(0,4);
    cpack.code_class.setVals(0,3);
    cpack.code_detail.setVals(1,5);
    cpack.msg_id.setVals(0x736A,16);
    cpack.token.setVals(0,0);

    coap_option uri_host;
    uri_host.number.setVals(3,4);
    uri_host.length.setVals(9,4);
    uri_host.type = coap_option::Type::string;
    std::string uri_host_str = "localhost";
    uri_host.value = strToByteVec(uri_host_str);
    cpack.options.push_back(uri_host);
}

/* Reads,parses and packages coap_packets from the text seed file
 * Assumes title line has already been read and disregarded form the stream
 * */
coap_packet parsePacket(std::ifstream& fs){
    std::string line;
    coap_packet cpack;
    setCoapDefaultVals(cpack);

    while(getline(fs,line)){
        if(line.compare("}") == 0){
            break;
        }
        std::vector<std::string> tokens = strSplit(line, ':');
        if(tokens.size() < 2){
            continue;
        }

        std::string id = tokens[0];
        std::string arg = tokens[1];
        if(id.compare("code") == 0){
            setCoapCode(cpack, arg);
        }else if(id.compare("uri") == 0){
            setCoapUri(cpack, arg);
        }else if(id.compare("val") == 0 ){
            if(tokens.size() >= 3){
                setParsedCoapPayload(cpack, arg, tokens[2]);
            }else{
                setParsedCoapPayload(cpack, tokens[1]);
            }
        }else{
            std::cout << "Unrecognized packet code: " << id << " with value: " << arg << "\n";
        }
    }
    return cpack;
}

std::vector<coap_packet> readPacketFile(std::string filePath){
    std::vector<coap_packet> vec;
    
    std::ifstream fs(filePath);
    std::string line;
    while(getline(fs,line)){
        std::vector<std::string> s = strSplit(line, ':');
        if(s.size() > 1 && s[1].compare("{")==0){
            coap_packet cpack = parsePacket(fs);
            vec.push_back(cpack);
        }
    }
    std::cout << "\n";
    return vec;
}


#endif
