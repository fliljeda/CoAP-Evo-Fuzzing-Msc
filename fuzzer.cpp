#include "packet_handler.cpp"
#include "server_handler.cpp"
#include <limits.h>
#include "coap_mutations.cpp"


#ifndef COAP_FUZZER
#define COAP_FUZZER

enum OpType{UINT,STRING,OPAQUE,EMPTY};


struct m_option{
    std::string name;
    int number;
    OpType type;
    int min_size;
    int max_size;
};

std::vector<coap_packet> seed_packets;


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
void addOptionRandom(coap_packet& cpack){
    int opIdx = rand()%m_options.size();
    addOption(cpack,opIdx);
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

void setPayloadRandom(coap_packet& cpack, int maxsize = 100){
    int size = rand()%maxsize;
    cpack.payload.clear();
    for(int i = 0; i < size; i++){
        cpack.payload.push_back(std::byte(rand()%256));
    }
}


std::vector<std::pair<mutation_target, int>> m_target_tickets{
    {VERSION,1},
    {TYPE,3},
    {TOKEN_LENGTH,2},
    {CODE_CLASS,3},
    {CODE_DETAIL,3},
    {MSG_ID,5},
    {TOKEN,5},
    {OPTION,30},
    {PAYLOAD,15},
};


mutation_target pickTarget(){
    int num_of_tickets = 0;
    for(const auto& p: m_target_tickets){
        num_of_tickets += p.second;
    }
    int winner = rand()%num_of_tickets;
    int index = 0;
    while((winner -= m_target_tickets[index].second) >= 0){
        index++;
    }
    return m_target_tickets[index].first;
}

void checkForKnownErrors(coap_packet& cpack){
    //Option with number 0x0B and length 0
    for(size_t i = 0; i < cpack.options.size(); i++){
        coap_option& op = cpack.options[i];
        if(op.number.value == 0x0B && op.length.value == 0){
            std::cout << "Found known error in coap packet, erasing it\n";
            cpack.options.erase(cpack.options.begin() + i);
            i--;
        }
    }
}

/* A packet mutation either mutates, adds or changes either options,
 * certain fields or payload */
void packetMutation(coap_packet& cpack){
    mutation_target target = pickTarget();
    mutation_rule rule;
    
    int mutate_bit_perc = 30;
    
    bool bitflip = 0;
    if(rand()%100 < mutate_bit_perc){
        if(target != OPTION){
            mutate(cpack, target, BITFLIP);
            return ;
        }else{
            bitflip = 1;
        }
    }

    switch(target){
        case VERSION:
            rule = uint_rules[rand()%uint_rules.size()];
            mutate(cpack, target, rule);
            break;
        case TYPE:
            rule = uint_rules[rand()%uint_rules.size()];
            mutate(cpack, target, rule);
            break;
        case TOKEN_LENGTH:
            rule = uint_rules[rand()%uint_rules.size()];
            mutate(cpack, target, rule);
            break;
        case CODE_CLASS:
            rule = uint_rules[rand()%uint_rules.size()];
            mutate(cpack, target, rule);
            break;
        case CODE_DETAIL:
            rule = uint_rules[rand()%uint_rules.size()];
            mutate(cpack, target, rule);
            break;
        case MSG_ID:
            rule = uint_rules[rand()%uint_rules.size()];
            mutate(cpack, target, rule);
            break;
        case TOKEN:
            rule = uint_rules[rand()%uint_rules.size()];
            mutate(cpack, target, rule);
            break;
        case OPTION:{
            if(cpack.options.size() == 0){
                addOption(cpack, rand()%m_options.size());
                return;
            }
            int addOrRemove = 10;
            if(rand()%100 < addOrRemove){
                if(rand()%2){
                    addOption(cpack, rand()%m_options.size());
                }else{
                    cpack.options.erase(cpack.options.begin() + (rand()%cpack.options.size()));
                }
                return;
            }
            
            coap_option& op = cpack.options[rand()%cpack.options.size()];
            switch(op.type){
                case coap_option::empty:
                    rule = empty_rules[rand()%empty_rules.size()];
                    break;
                case coap_option::opaque:
                    rule = opaque_rules[rand()%opaque_rules.size()];
                    break;
                case coap_option::uint:
                    rule = uint_rules[rand()%uint_rules.size()];
                    break;
                case coap_option::string:
                    rule = string_rules[rand()%string_rules.size()];
                    break;
            }
            mutate_option(op, bitflip ? BITFLIP : rule);

            }
            break;
        case PAYLOAD:
            rule = payload_rules[rand()%payload_rules.size()];
            mutate(cpack, target, rule);
            break;
    }
    checkForKnownErrors(cpack);
}


/* Generates a single packet by selecting from seed and randomly set two atttributes, either
 * options or other fields*/
coap_packet generatePacket(){
    coap_packet cpack;
    if(seed_packets.size() != 0){
        int seed_idx = rand()%seed_packets.size();
        cpack = seed_packets[seed_idx];
    }

    for(size_t i = 0; i < 2; i++){
        mutation_target targ = pickTarget();
        switch(targ){
            case VERSION:
            case TYPE:
            case MSG_ID:
                setMsgIdRandom(cpack);
                break;
            case TOKEN_LENGTH:
            case TOKEN:
                setTokenRandom(cpack);
                break;
            case CODE_CLASS:
                setCodeClassRandom(cpack);
                break;
            case CODE_DETAIL:
                setCodeDetailRandom(cpack);
                break;
            case PAYLOAD:
                setPayloadRandom(cpack);
                break;
            case OPTION:
                addOptionRandom(cpack);
                break;

        }
    }
    
    return cpack;
}

/* A session mutation mutates two random packets in the session */
void sessionMutation(std::vector<coap_packet>& sessions){
    int pos1 = rand()%sessions.size();
    int pos2 = rand()%sessions.size();
    packetMutation(sessions[pos1]);
    packetMutation(sessions[pos2]);
}

/* A session mutation mutates the two packets indexed by parameters in the session */
void sessionMutation(std::vector<coap_packet>& sessions, int a, int b){
    packetMutation(sessions[a]);
    packetMutation(sessions[b]);
}

/* Is done BOTH initially when generating pools and when performing crossovers on pools */
std::vector<coap_packet> generateSession(int session_size){
    std::vector<coap_packet> session;
    for(int i = 0; i < session_size; i++){
        session.push_back(generatePacket());
    }
    return session;
}

/* A pool mutation either adds, remove or both add and removes
 * sessions from the pool. The added session is created from the seed packets
 * and generated with the generation engine. This function is used to modify
 * the pool */
void poolMutation(std::vector<std::vector<coap_packet>>& pool, int session_size, bool fixed = 1){
    
    //Cant be first index, due to evolutioanry reasons (assumes pool is sorted by fitness)
    auto erase_iterator = (pool.begin()+1) + rand()%(pool.size()-1); 

    if(fixed){
        pool.erase(erase_iterator); //erases 1 element
        pool.push_back(generateSession(session_size));
    }else{
        int decision = rand()%100;
        if(decision < 50){
            pool.erase(erase_iterator);
        }else{
            pool.push_back(generateSession(session_size));
        }
    }
}

/* Is done initially */
std::vector<std::vector<coap_packet>> generatePool(int pool_size, int session_size){
    std::vector<std::vector<coap_packet>> pool;
    for(int i = 0; i < pool_size; i++){
        pool.push_back(generateSession(session_size));
    }

    return pool;
}

/* Mixes two sessions into a new one. Does not modify existing sessions */
std::vector<coap_packet> sessionCrossover(const std::vector<coap_packet>& a, const std::vector<coap_packet>& b, size_t crossover_point){
    std::vector<coap_packet> cross;
    if(a.size() < crossover_point || b.size() < crossover_point){
        std::cout << "Can't crossover on index larger than session array\n";
        return a;
    }

    for(size_t i = 0; i < crossover_point; i++){
        cross.push_back(a[i]);
    }

    for(size_t i = crossover_point; i < b.size(); i++){
        cross.push_back(b[i]);
    }

    return cross;
}

/* Mixes two pools */
std::vector<std::vector<coap_packet>> poolCrossover(const std::vector<std::vector<coap_packet>>& a, 
        const std::vector<std::vector<coap_packet>>& b, 
        size_t crossover_point){
    std::vector<std::vector<coap_packet>> cross;
    if(a.size() < crossover_point || b.size() < crossover_point){
        std::cout << "Can't crossover on index larger than the pool array\n";
        return a;
    }

    for(size_t i = 0; i < crossover_point; i++){
        cross.push_back(a[i]);
    }

    for(size_t i = crossover_point; i < b.size(); i++){
        cross.push_back(b[i]);
    }

    return cross;
}

std::vector<coap_packet> getSeedFilePackets(){
    std::vector<coap_packet> cpacks = readPacketFile("./seed.txt");
    wkcore_packet = cpacks[0];
    seed_packets = cpacks;
    return cpacks;
}


#endif
