#include <stdint.h>
#include <vector>

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
