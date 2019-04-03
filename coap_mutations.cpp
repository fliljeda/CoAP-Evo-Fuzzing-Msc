#include "packet_handler.cpp"
#include "vector"
#include <cstddef>
#include <cstdlib>
#include <ctime>
#include <iostream>

#ifndef COAP_MUTATIONS
#define COAP_MUTATIONS


enum mutation_target{
    VERSION,
    TYPE,
    TOKEN_LENGTH,
    CODE_CLASS,
    CODE_DETAIL,
    MSG_ID,
    TOKEN,
    OPTION,
    PAYLOAD,
};

enum mutation_rule{
    STR_EMPTY,
    STR_PREDEFINED,
    STR_ADD_NON_PRINTABLE,
    STR_OVERFLOW,
    UINT_EMPTY,
    UINT_ABSOLUTE_MINUS_ONE,
    UINT_ABSOLUTE_ONE,
    UINT_ABSOLUTE_ZERO,
    UINT_ADD_ONE,
    UINT_SUBTRACT_ONE,
    UINT_MAX_RANGE,
    UINT_MIN_RANGE,
    UINT_MAX_RANGE_PLUS_ONE,
    OPAQUE_EMPTY,
    OPAQUE_PREDEFINED,
    OPAQUE_OVERFLOW,
    EMPTY_PREDEFINED,
    EMPTY_ABSOLUTE_MINUS_ONE,
    EMPTY_ABSOLUTE_ONE,
    EMPTY_ABSOLUTE_ZERO,
    PAYLOAD_EMPTY,
    PAYLOAD_PREDEFINED,
    PAYLOAD_ADD_NON_PRINTABLE,
    BITFLIP
};


template<typename T>
T getMaxVal(coap_field<T>& field){
    if(field.valid_min != 0 || field.valid_max != 0){
        return field.valid_max;
    }
    T res = 1;
    for(T i = 0; i < field.bits; i++){
        res *= 2;
    }
    return res-1;
}

template<typename T>
T getMinVal(coap_field<T>& field){
    if(field.valid_min != 0 || field.valid_max != 0){
        return field.valid_min;
    }
    return 0;
}

/* Generates a predefined string using an alphabet and a random length between the parameter
 * values
 * TODO Add utf8*/
std::vector<std::byte> genPredefinedString(int sizeMin = 1, int sizeMax = 65502){
    std::vector<std::byte> vec;
    std::vector<char> alphabet({'\0','a','A','.','\\','%'});
    int size = sizeMin + (rand()%(sizeMax-sizeMin+1));
    for(int i = 0; i < size; i++){
        int rNum = rand()%(alphabet.size());
        vec.push_back(std::byte(alphabet[rNum]));
    }
    return vec;
}

/* Generates a predefined string using an alphabet and a random length between the parameter
 * values */
std::vector<std::byte> genPredefinedBinaryString(int sizeMin = 1, int sizeMax = 65502){
    std::vector<std::byte> vec;
    int size = 1 + (rand()%(sizeMax));
    for(int i = 0; i < size; i++){
        int rNum = rand()%(256);
        vec.push_back(std::byte(rNum));
    }
    return vec;
}

std::byte getUnprintableChar(){
    int c = rand()%32;
    return std::byte(c);
}

std::byte getRandomEmptyChar(){
    std::vector<char> alphabet({'\xff','%','#','\0','8'});
    int rNum = rand()%(alphabet.size());
    return std::byte(rNum);
}

int mutate_payload(std::vector<std::byte>& payload, mutation_rule rule){
    switch(rule){
        case PAYLOAD_EMPTY:
            payload.clear();
            break;
        case PAYLOAD_PREDEFINED:
            payload = genPredefinedBinaryString(1,65502);
            break;
        case PAYLOAD_ADD_NON_PRINTABLE:
            payload.push_back(getUnprintableChar());
            break;
        case BITFLIP:
            {
            if(payload.size() < 1) return 1;
            int bit_pos = rand()%(payload.size()*8);
            int idx = bit_pos / 8;
            int offset = bit_pos % 8;
            payload[idx] ^= std::byte((1 << offset));
            }
            break;
        default:
            return -1;
    }
    return 0;
}

/* Mutations on a string (byte array) field. Used in options */
int mutate_field(coap_field<std::vector<std::byte>>& field, mutation_rule rule){
    int prev_bits = field.bits;
    std::vector<std::byte> prev_val = field.value;
    std::vector<std::byte> predefined_str;
    std::byte tmp;
    switch(rule){
        case STR_EMPTY:
            field.setVals(std::vector<std::byte>(), 0);
            break;
        case STR_PREDEFINED:
           
            predefined_str = genPredefinedString(field.valid_min, field.valid_max);
            field.setVals(predefined_str,predefined_str.size()*8);
            break;
        case STR_ADD_NON_PRINTABLE:
            prev_val.push_back(getUnprintableChar());
            field.setVals(prev_val,prev_bits+8);
            break;
        case STR_OVERFLOW:
            tmp = prev_val.size() > 0 ? prev_val[prev_val.size()-1] : std::byte('\0');
            for(int i = prev_val.size(); i <= field.valid_max+1; i++){ //until max has been reached and one more
                prev_val.push_back(tmp);
                prev_bits += 8;

            }
            field.setVals(prev_val,prev_bits);
            break;
        case OPAQUE_EMPTY:
            field.setVals(std::vector<std::byte>(), 0);
            break;
        case OPAQUE_PREDEFINED:
            predefined_str = genPredefinedBinaryString(field.valid_min, field.valid_max);
            field.setVals(predefined_str,predefined_str.size()*8);
            break;
        case OPAQUE_OVERFLOW:
            for(int i = prev_val.size(); i <= field.valid_max+1; i++){ //until max has been reached and one more
                prev_val.push_back(std::byte(rand()%255));
                prev_bits += 8;
            }
            field.setVals(prev_val,prev_bits);
            break;
        case EMPTY_PREDEFINED:
            prev_val.clear();
            prev_val.push_back(getRandomEmptyChar());
            field.setVals(prev_val,8);
            break;
        case EMPTY_ABSOLUTE_MINUS_ONE:
            prev_val.clear();
            prev_val.push_back(std::byte(-1));
            field.setVals(prev_val,8);
            break;
        case EMPTY_ABSOLUTE_ONE:
            prev_val.clear();
            prev_val.push_back(std::byte(1));
            field.setVals(prev_val,8);
            break;
        case EMPTY_ABSOLUTE_ZERO:
            prev_val.clear();
            prev_val.push_back(std::byte(0));
            field.setVals(prev_val,8);
            break;
        case BITFLIP:
            {
            if(prev_val.size() < 1) return 1;
            int bit_pos = rand()%prev_bits;
            int idx = bit_pos / 8;
            int offset = bit_pos % 8;
            prev_val[idx] ^= std::byte((1 << offset));
            field.setVals(prev_val, prev_bits);
            }
            break;
        default:
            return -1;
            break;
    }
    return 0;
}

template<class T>
T mutate_field(coap_field<T>& field, mutation_rule rule){
    T t = 0; t++; t |= t;
    int prev_bits = field.bits;
    T prev_val = field.value;
    int bit_pos;
    switch(rule){
        case UINT_EMPTY:
            field.setVals(0,0);
            break;
        case UINT_ABSOLUTE_MINUS_ONE:
            field.setVals(-1,prev_bits);
            break;
        case UINT_ABSOLUTE_ONE:
            field.setVals(1, prev_bits);
            break;
        case UINT_ABSOLUTE_ZERO:
            field.setVals(0, prev_bits);
            break;
        case UINT_ADD_ONE:
            field.setVals(prev_val+1, prev_bits);
            break;
        case UINT_SUBTRACT_ONE:
            field.setVals(prev_val-1, prev_bits);
            break;
        case UINT_MAX_RANGE:
            field.setVals(getMaxVal(field), prev_bits);
            break;
        case UINT_MIN_RANGE:
            field.setVals(getMinVal(field), prev_bits);
            break;
        case UINT_MAX_RANGE_PLUS_ONE:
            field.setVals(getMaxVal(field)+1, prev_bits);
            break;
        case BITFLIP:
            if(prev_bits == 0) return 1;
            bit_pos = rand()%prev_bits;
            prev_val ^= 1 << bit_pos;
            field.setVals(prev_val, prev_bits);
            break;
        default:
            return -1;
            break;
    }
    return 0;
}

void mutate_option(coap_option& opt, mutation_rule rule, bool adjustFormat = 1){
    switch(rule){
        case STR_EMPTY:
            if(adjustFormat){
                opt.length.setVals(0,4);
                opt.optional_length.setVals(0,0);
            }
            opt.setValue("");
            break;
        case STR_PREDEFINED:{
                std::vector<std::byte> predefined;
                int valLength = opt.calcLength();
                if(adjustFormat){
                    predefined = genPredefinedString(valLength, valLength);
                    opt.setLength(predefined.size());
                }else{
                    predefined = genPredefinedString(valLength-4, valLength+4);
                }
                opt.value = predefined;
            }
            break;
        case STR_ADD_NON_PRINTABLE:{
                std::vector<std::byte> predefined;
                opt.value.push_back(getUnprintableChar());
                if(adjustFormat){
                    opt.setLength(predefined.size());
                    opt.setLength(opt.value.size()+1);
                }else{
                }
                opt.value = predefined;
            }
            break;
        case STR_OVERFLOW:{
                std::byte tmp = opt.value.size() > 0 ? opt.value[opt.value.size()-1] : std::byte('\0');
                int addNum = opt.valid_max_size != -1 ? opt.valid_max_size : opt.calcLength()+4;
                int currNum = opt.value.size();
                for(int i = opt.value.size(); i <= addNum-currNum; i++){ //until max has been reached and one more
                    opt.value.push_back(tmp);
                }
                if(adjustFormat){
                    opt.setLength(opt.value.size());
                }
            }
            break;
        case UINT_EMPTY:
            opt.setValue(0,0);
            if(adjustFormat){
                opt.setLength(0);
            }else{
            }
            break;
        case UINT_ABSOLUTE_MINUS_ONE:
            opt.setValue(-1,1);
            if(adjustFormat){
                opt.setLength(1);
            }else{
            }
            break;
        case UINT_ABSOLUTE_ONE:
            opt.setValue(1, 1);
            if(adjustFormat){
                opt.setLength(1);
            }else{
            }
            break;
        case UINT_ABSOLUTE_ZERO:
            opt.setValue(0, 1);
            if(adjustFormat){
                opt.setLength(1);
            }else{
            }
            break;
        case UINT_ADD_ONE:
            opt.setValue(opt.getIntVal() + 1, opt.calcLength());
            break;
        case UINT_SUBTRACT_ONE:
            opt.setValue(opt.getIntVal() - 1, opt.calcLength());
            break;
        case UINT_MAX_RANGE:
            opt.setValue((unsigned int)-1, opt.valid_max_size);
            break;
        case UINT_MIN_RANGE:
            opt.setValue((unsigned int)0, opt.valid_min_size);
            break;
        case UINT_MAX_RANGE_PLUS_ONE:
            //Add one more 0x1 byte at the end
            opt.setValue(((unsigned int)-1) & (0x1 << opt.valid_max_size*8), opt.valid_max_size+1);
            break;
        case OPAQUE_EMPTY:
            if(adjustFormat){
                opt.length.setVals(0,4);
                opt.optional_length.setVals(0,0);
            }
            opt.setValue("");
            break;
        case OPAQUE_PREDEFINED:{
                std::vector<std::byte> predefined;
                int valLength = opt.calcLength();
                if(adjustFormat){
                    predefined = genPredefinedBinaryString(valLength, valLength);
                    opt.setLength(predefined.size());
                }else{
                    predefined = genPredefinedBinaryString(valLength-4, valLength+4);
                }
                opt.value = predefined;
            }
            break;
        case OPAQUE_OVERFLOW:{
                int addNum = opt.valid_max_size != -1 ? opt.valid_max_size : opt.calcLength()+4;
                int currNum = opt.value.size();
                for(int i = opt.value.size(); i <= addNum-currNum; i++){ //until max has been reached and one more
                    opt.value.push_back(std::byte(rand()%255));
                }
                if(adjustFormat){
                    opt.setLength(opt.value.size());
                }
            }
            break;
        case EMPTY_PREDEFINED:
            opt.value.clear();
            opt.value.push_back(getRandomEmptyChar());
            opt.setLength(1);
            break;
        case EMPTY_ABSOLUTE_MINUS_ONE:
            opt.value.clear();
            opt.value.push_back(std::byte(-1));
            opt.setLength(1);
            break;
        case EMPTY_ABSOLUTE_ONE:
            opt.value.clear();
            opt.value.push_back(std::byte(1));
            opt.setLength(1);
            break;
        case EMPTY_ABSOLUTE_ZERO:
            opt.value.clear();
            opt.value.push_back(std::byte(0));
            opt.setLength(1);
            break;
        default:
            return;
    }
}


/* Takes in a copy of the coap_packet, performs a mutation and returns the copy */
coap_packet mutate(coap_packet cpack, mutation_target target, mutation_rule rule){
    switch(target){
        case VERSION:
            mutate_field(cpack.version, rule);
            break;
        case TYPE:
            mutate_field(cpack.type, rule);
            break;
        case TOKEN_LENGTH:
            mutate_field(cpack.token_length, rule);
            break;
        case CODE_CLASS:
            mutate_field(cpack.code_class, rule);
            break;
        case CODE_DETAIL:
            mutate_field(cpack.code_detail, rule);
            break;
        case MSG_ID:
            mutate_field(cpack.msg_id, rule);
            break;
        case TOKEN:
            mutate_field(cpack.token, rule);
            break;
        case OPTION:
            std::cout << "Called mutate on option in wrong place. Use mutate_option instead\n";
            break;
        case PAYLOAD:
            mutate_payload(cpack.payload, rule);
            break;
        default:
        return cpack;
    }
    return cpack;
}

#endif
