#include <stdint.h>
#include <vector>
#include <cstddef>
#include <iostream>


template<typename T>
struct coap_field{
    T value;
    int bits;

    void setVals(T val, int bits){
        this->value = val;
        this->bits = bits;
    }
};

struct coap_option{
    coap_field<int> number{0,4};
    coap_field<int> length{0,4};
    coap_field<int> optional_length;
    coap_field<int> optional_delta;
    enum Type {empty, opaque, uint, string};
    Type type;
    void* value;

    template<typename T>
    T& getVal() const{
        return *(T*)(value);
    }
};

struct coap_packet{

    //Header
    coap_field<int> version{1,2};
    coap_field<int> type{1,2};
    coap_field<int> token_length{0,4};
    coap_field<int> code_class{0,3};
    coap_field<int> code_detail{0,5};
    coap_field<int> msg_id{0,16};

    //Token
    coap_field<int64_t> token{0,64};

    //Options
    std::vector<coap_option> options;

    //Payload
    coap_field<int> payload_marker{0xFF,8};
    void* payload = nullptr;

};

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
int writeCoapField(std::vector<std::byte>& vec, const coap_field<T>& field, int pos){
    return writeBits(vec, field.value, pos, field.bits);
}

/* Writes each vector element using the allocated sizes of the elements
 * Calculates the allocated sizes with sizeof*/ 
template<typename T>
int writeCoapVector(std::vector<std::byte>& vec, const std::vector<T>& val, int pos){
    for(size_t i = 0; i < val.size(); i++){
        pos = writeBits(vec, val[i], pos, sizeof(val[i])*8);
    }
    return pos;
}

int writeCoapOptions(std::vector<std::byte>& vec, const std::vector<coap_option>& options, int pos){
    int prevOptNum = 0;
    for(size_t i = 0; i < options.size(); i++){
        pos = writeBits(vec, options[i].number.value - prevOptNum, pos, options[i].number.bits);
        pos = writeCoapField(vec, options[i].length, pos);
        prevOptNum = options[i].number.value;

        int valLength = options[i].length.value;
        switch (options[i].type){
            case coap_option::Type::empty:{
                //Write nothing
            }
            break;

            case coap_option::Type::opaque:{
                //cast to vector<byte>
                std::vector<std::byte> val = options[i].getVal<std::vector<std::byte>>();
                pos = writeCoapVector(vec, val, pos);
            }
            break;

            case coap_option::Type::uint:{
                //cast to unsigned int
                unsigned int val = options[i].getVal<unsigned int>();
                pos = writeBits(vec, val, pos, valLength);
            }
            break;

            case coap_option::Type::string:{
                //case to string
                std::vector<char> val = options[i].getVal<std::vector<char>>();
                pos = writeCoapVector(vec, val, pos);
            }
            break;
        }
    }
    return pos;
}


std::vector<std::byte> packPacket(const coap_packet& pac){
    std::vector<std::byte> vec;
    int pos = 0;   
    pos = writeCoapField(vec, pac.version, pos);
    pos = writeCoapField(vec, pac.type, pos);
    pos = writeCoapField(vec, pac.token_length, pos);
    pos = writeCoapField(vec, pac.code_class, pos);
    pos = writeCoapField(vec, pac.code_detail, pos);
    pos = writeCoapField(vec, pac.msg_id, pos);
    pos = writeBits(vec, pac.token.value, pos, pac.token.value);
    pos = writeCoapOptions(vec, pac.options, pos);
    return vec;
}
