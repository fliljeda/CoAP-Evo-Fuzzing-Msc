#include "packet_handler.cpp"
#include "server_handler.cpp"
#include <limits.h>



enum OpType{UINT,STRING,OPAQUE,EMPTY};

struct m_option{
    std::string name;
    int number;
    OpType type;
    int min_size;
    int max_size;
};


std::vector<m_option> m_options = {
    m_option{"If-Match",1,OPAQUE,0,2},
    m_option{"Uri-Host",3,STRING,1,255},
    m_option{"ETag",4,OPAQUE,1,8},
    m_option{"If-None-Match",5,EMPTY,0,0},
    m_option{"Uri-Port",7,UINT,0,2},
    m_option{"Location-Path",8,STRING,0,255},
    m_option{"Uri-Path",11,STRING,0,255},
    m_option{"Content-Format",12,UINT,0,2},
    m_option{"Max-Age",14,UINT,0,4},
    m_option{"Uri-Query",15,STRING,0,255},
    m_option{"Accept",17,UINT,0,2},
    m_option{"Location-Query",20,STRING,0,255},
    m_option{"Proxy-Uri",35,STRING,1,1034},
    m_option{"Proxy-Scheme",36,STRING,1,255},
    m_option{"Size1",60,UINT,0,4},
};

std::vector<unsigned int> uint_seed = {
    0,1,2,255,256,65502,UINT_MAX, UINT_MAX-1, UINT_MAX/2
};
std::vector<std::string> string_seed = {
    "", "\xFF",  "\x00", "test", "\xFF\xFF" 
};
std::vector<std::vector<std::byte>> opaque_seed = {
    {std::byte(0)},{std::byte(255)},{std::byte(255),std::byte(255),std::byte(255),std::byte(255)},{std::byte(0),std::byte(0),std::byte(0),std::byte(0)}
};
std::vector<std::vector<std::string>> uri_paths = {
    {"localhost", ".well-known", "core"}, {"localhost","light"}, {"localhost","time"}
};

void setLimits(coap_option& cop, m_option& m_op){
    cop.valid_min_size = m_op.min_size;
    cop.valid_max_size = m_op.max_size;
}

void addValidUri(coap_packet& cpack, m_option m_op){
    std::vector<std::string> path = uri_paths[rand()%uri_paths.size()];
    for(size_t i = 0; i < path.size(); i++){
        coap_option cop;

        cop.number.setVals(11, 4);
        cop.setValue(path[i]);
        cop.order = i;
        cop.type = coap_option::Type::string;
        setLimits(cop, m_op);
        cop.setLength(cop.value.size());
    }
}

OpType setValue(coap_option& cop, m_option& m_op){
    switch(m_op.type){
        case UINT:{
            unsigned int n = uint_seed[rand()%uint_seed.size()];
            cop.setValue(n, 4);
            return UINT;
        }
        case STRING:{
            std::string s = string_seed[rand()%string_seed.size()];
            cop.setValue(s);
            return STRING;
        }
        case OPAQUE:{
            std::vector<std::byte> bytes = opaque_seed[rand()%opaque_seed.size()];
            cop.value = bytes;
            return OPAQUE;
        }
        case EMPTY:
            cop.value.clear();
            return EMPTY;
        default:
            return OPAQUE;
    }
}

OpType setType(coap_option& cop, m_option& m_op){
    switch(m_op.type){
        case UINT:
            cop.type = coap_option::Type::uint;
            return UINT;
        case STRING:
            cop.type = coap_option::Type::string;
            return STRING;
        case OPAQUE:
            cop.type = coap_option::Type::opaque;
            return OPAQUE;
        case EMPTY:
            cop.type = coap_option::Type::empty;
            return EMPTY;
        default:
            return OPAQUE;
    }
}

void addOption(coap_packet& cpack, int opIdx){
    m_option m_op = m_options[opIdx];
    if(opIdx == 11){
        addValidUri(cpack, m_op);
    }else{
        coap_option cop;
        setType(cop, m_op);
        cop.number.setVals(m_op.number, 4);
        setValue(cop, m_op);
        setLimits(cop, m_op);
        cop.setLength(cop.value.size());
        cpack.options.push_back(cop);
    }

    std::sort(cpack.options.begin(), cpack.options.end(), [](coap_option a, coap_option b){
            if(a.number.value == b.number.value){
                return a.order > b.order;
            }
            return a.number.value > b.number.value;
    });
}
void addOption(coap_packet& cpack, std::string opName){
    for(size_t i = 0; i < m_options.size(); i++){
        //TODO ADD this option to the packet. Maybe sort the options to make it appropriate
        if(m_options[i].name.compare(opName) == 0){
            addOption(cpack, i);           
        }
    }
}
void printOptions(coap_packet& cpack){
    for(size_t i = 0; i < cpack.options.size(); i++){
        for(size_t j = 0; j < cpack.options[i].value.size(); j++){
            printf("%c", (unsigned char)cpack.options[i].value[j]);
        }
        printf(" ");
    }
    cout << "\n";
}

template<typename T>
T getBitSize(T val){
    int bits = 0;
    while(val){
        val >>= 1;
        bits++;
    }
    return bits;
}

void setMsgId(coap_packet& cpack, int value){
    cpack.msg_id.setVals(value,cpack.msg_id.bits);
}
void setMsgIdRandom(coap_packet& cpack){
    setMsgId(cpack, rand());
}

void setToken(coap_packet& cpack, int64_t value, bool validLength = 1){
    int highestBit = validLength ? getBitSize<int64_t>(value) : cpack.token.bits;
    cpack.token.setVals(value, highestBit);
}
void setTokenRandom(coap_packet& cpack, bool validLength = 1){
    int64_t val = ((int64_t)rand() << 32) | (int)rand();
    setToken(cpack, val, validLength);
}

void setCodeClass(coap_packet& cpack, int value){
    cpack.code_class.setVals(value, cpack.code_class.bits);
}
void setCodeClassRandom(coap_packet& cpack){
    int val = rand()%cpack.code_class.valid_max;
    setCodeClass(cpack, val);
}

void setCodeDetail(coap_packet& cpack, int value){
    cpack.code_detail.setVals(value, cpack.code_detail.bits);
}
void setCodeDetailRandom(coap_packet& cpack){
    int val = rand()%cpack.code_detail.valid_max;
    setCodeDetail(cpack, val);
}

std::vector<coap_packet> getSeedFilePackets(){
    std::vector<coap_packet> cpacks = readPacketFile("./seed.txt");
    return cpacks;
}
