#include "packet_handler.cpp"
#include "server_handler.cpp"



enum OpFormat{UINT,STRING,OPAQUE,EMPTY};

struct m_option{
    std::string name;
    int number;
    OpFormat format;
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

void addOption(coap_packet& cpack, std::string opName){
    for(size_t i = 0; i < m_options.size(); i++){
        //TODO ADD this option to the packet. Maybe sort the options to make it appropriate

    }
}

std::vector<coap_packet> getSeedFilePackets(){
    std::vector<coap_packet> cpacks = readPacketFile("./seed.txt");
    return cpacks;
}
