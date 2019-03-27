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
    T& getVal(){
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
        std::byte mask = std::byte(((value >> (n_bits-1)) & 1) << shift);

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
int writeBits(std::vector<std::byte>& vec, const coap_field<T>& field, int pos){
    return writeBits(vec, field.value, pos, field.bits);
}



std::vector<std::byte> packPacket(const coap_packet& pac){
    std::vector<std::byte> vec;
    int pos = 0;   
    pos = writeBits(vec, pac.version, pos);
    pos = writeBits(vec, pac.type, pos);
    pos = writeBits(vec, pac.token_length, pos);
    pos = writeBits(vec, pac.code_class, pos);
    pos = writeBits(vec, pac.code_detail, pos);
    pos = writeBits(vec, pac.msg_id, pos);
    return vec;
}
