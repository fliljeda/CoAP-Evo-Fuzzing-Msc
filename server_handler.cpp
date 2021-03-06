#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <regex>
#include <sys/wait.h>
#include <experimental/filesystem>
#include <vector>
#include <cstddef>
#include "network_handler.cpp"
#include "packet_handler.cpp"
#include "logger.cpp"

#ifndef COAP_SERVER_HANDLER
#define COAP_SERVER_HANDLER


using namespace std;
namespace fsys = std::experimental::filesystem;

coap_packet wkcore_packet;

struct configuration{
    bool ready;
    string coapExeCmd;
    string logDir;
    string dumpOpt;
    string coapBinName;
    string moduleStr;
} configs;

struct basic_block {
    size_t number;
    int occurrances = 0;
};



struct {
    /* Used as a static pool code coverage structure. Will remain between sessions */
    bool active = 0;
    std::vector<basic_block> vec;
} poolCov;

/* Returns a Y-m-d string of now */
string getNowDateString(){
        std::time_t now_c = time(nullptr);
        char time[20];
        strftime(time, sizeof(time), "%F", localtime(&now_c));
        return string(time);
}

string stringConcat(const vector<string>& l, string separator = ""){
    string tmp = "";
    for(size_t i = 0; i < l.size(); i++){
        tmp.append(l[i]);
        if(i != l.size()-1){
            tmp.append(separator);
        }
    }
    return tmp;
}

/* If dynamorio starts other processes, unnecessary log files may be created
 * This function serves as a cleaner for the log dir.*/
void cleanLogDir(){
    //cout << "Cleaning logdir: " << configs.logDir << " of unnecessary logfiles\n";

    for(fsys::directory_entry p: fsys::directory_iterator(configs.logDir)){
        string filename = p.path().filename();
        if(filename.find(configs.coapBinName) == std::string::npos){
            fsys::remove(p.path());
        }
    }
}



/* Checks the log directory if there is a directory in it for today's log
 * If so: append that directory to the logdir path
 * If not: create the directory and append it to path*/
bool setCurrentLogdir(const string& logDirConf){
    string logDir = logDirConf;
    string dateStr = getNowDateString();
    bool dirExists = 0;
    if(!fsys::is_directory(logDir)){
        //cout << "Could not find directory " << logDir << " to write logs in, using /tmp/" << "\n";
        logDir = "/tmp/";
    }
    for(fsys::directory_entry p: fsys::directory_iterator(logDir)){
        if(!fsys::is_directory(p)){
            continue;
        }
        string fName = (string)(p.path().filename());
        if(fName.compare(dateStr) == 0){
            dirExists = 1;
            break;
        }
    }
    string newPath = logDir[logDir.size() - 1] == '/' ?
        logDir.append(dateStr).append("/") :
        logDir.append("/").append(dateStr).append("/") ;
    if(!dirExists){
         int res = fsys::create_directory(newPath);
         if(!res){
             return 0;
         }
    }    

    configs.logDir = newPath;
    return 1;
}

/* Reads configs from a file. Whitespace sensitive  */
void readConfig(string filePath = "./config.txt"){
    ifstream fs(filePath);
    string line;
    while(getline(fs,line)){
        size_t i = 0;
        string option = "";
        string value = "";
        for(; i < line.length() && (line[i] != '='); i++){
            option.push_back(line[i]);
        }
        i++; //expend =
        for(; i < line.length(); i++){
            value.push_back(line[i]);
        }
        if(value.length() == 0){
            continue;
        }
        if(option.compare("coapexecmd") == 0){
            configs.coapExeCmd = value;
        }else if(option.compare("logdir") == 0){
            configs.logDir = value;
            int res = setCurrentLogdir(configs.logDir);
            if(!res){
                cout << "Failed to find correct log folder and could not create one\n";
            }
        }else if(option.compare("dumpopt") == 0){
            configs.dumpOpt = value;
        }else if(option.compare("coapbinname") == 0){
            configs.coapBinName = value;
        }else if(option.compare("modulestr") == 0){
            configs.moduleStr = value;
        }
    }
    configs.ready = 1;
}

/* Sleep for @param milliseconds*/
void sleepMs(long milliseconds){
    struct timespec tim1, tim2;
    tim1.tv_sec = milliseconds/1000L;
    tim1.tv_nsec = ((long)milliseconds%1000) * 1000000L;
    
    nanosleep(&tim1, &tim2);
}

bool addBB(size_t num, vector<basic_block>& v){
    for(size_t i = 0; i < v.size(); i++){
        if(v[i].number == num){
            v[i].occurrances++;
            return 1;
        }
    }
    basic_block bb;
    bb.number = num;
    bb.occurrances = 1;
    v.push_back(bb);
    return 1;
}


/*Find module ID of the targetted application
 *Searches the table for lines that contain the name 
 * Returns the module ID or -1 if it can't be found  */
vector<int> findMod(ifstream &fs, string moduleStr){
    string str;
    int count;
    vector<int> modules;
    while(getline(fs,str)){
        if(str.rfind("Module Table: ", 0)==0){
            regex rgx("count (\\d+)");
            smatch m;
            regex_search(str, m, rgx);
            count = stoul(m[1], nullptr, 10);
            break;
        }
    }
    getline(fs,str); //Expend table header

    for(int i = 0; i < count; i++){
        getline(fs,str);
        if(str.find(moduleStr) != string::npos){
            int start = str.find(',')+1;
            int end = str.find(',', start);
            string modField = str.substr(start, end-start);
            int modId = stoul(modField, nullptr, 10);
            if(std::find(modules.begin(), modules.end(), modId) == modules.end()){
                   modules.push_back(modId);
                   //cout << "modId: " << modId << "\n";
            }
        }
    }
    return modules;
}

//Parses the BB lines of the file. Adding unique BB as elements of the returned vector
vector<basic_block> calcBasicBlocks(ifstream& fs, vector<int> selectedMods){ 
    string str = "";
    int numOfChosenBB = 0;
    int calcedNumOfBB = 0;
    //int numOfBB = 0;
    vector<basic_block> v;
    while(getline(fs,str)){

        if(str.rfind("BB Table", 0) == 0){ //if found word is at beginning
            regex rgx("\\d+");
            smatch match;
            if(regex_search(str, match ,rgx)){
                //numOfBB = stoul(match[0], nullptr, 10);
            }

        }
        
        if(str.rfind("module", 0) == 0){ //if found word is at beginning
            size_t start = str.find('[')+1;
            size_t end = str.find(']', start);
            bool isBB = start != string::npos && end != string::npos;
            if(!isBB){
                continue;
            }
            calcedNumOfBB++;
            string moduleStr = str.substr(start, end-start);
            int module = stoul(moduleStr, nullptr, 10);

            if(find(selectedMods.begin(), selectedMods.end(), module) != selectedMods.end() 
                    || selectedMods.empty() ){
                numOfChosenBB++;
                string sub = str.substr(13,18); //Fixed length 
                size_t num = stoul(sub, nullptr, 16);

                addBB(num, v);
                if(poolCov.active){
                    addBB(num, poolCov.vec);
                }
            }
        }
    }
    return v;
}

/* Parses a coverage file created with dynamorio 
 * param pathToFile is the relative 
 * param moduleStr is the keyword to look for in the files to determine what modules to include*/
int parseDrcov(string pathToFile, string moduleStr){

    ifstream fs(pathToFile);

    //If we only want to parse from a selected mod§
    bool isModSelected = moduleStr.empty() ? 0 : 1; 
    vector<int> selectedMods;
    if(isModSelected){
        selectedMods = findMod(fs, moduleStr);
        if(selectedMods.empty()){
            cout << "COULD NOT FIND THE MODULE CONTAINING: " << moduleStr << "\n";
            cout << "CONTINUING CALCULATING ALL: " << moduleStr << "\n";
        }
    }

    vector<basic_block> uniqueBlocks = calcBasicBlocks(fs,selectedMods);
    return uniqueBlocks.size();
}

/* Look through the process list and checks if the files inside indicate that it
 * is named a certain way. 
 * Returns 1 if the process exists and is named as @param string name
 * Returns 0 if it is named otherwise and if it doesnt exist*/
bool isProcNamed(string pidStr, string name){
    string path = string("/proc/").append(pidStr).append("/task/").append(pidStr);
    if(!fsys::exists(path)){
        return 0;
    }
    
    ifstream fs(path.append("/status"));

    string line;
    getline(fs,line);
    if(line.find(name) != std::string::npos){
        return 1;
    }else{
        return 0;
    }

}
bool isProcNamed(int pid, string name){ return isProcNamed(to_string(pid), name);}


/* Looks through /proc/ to find the process named coap. CoAP is run with an extra shell and most likely
 * it is the guessed PID but there is no way to be sure
 * Retries the guess a number of times with delays between to increase probability of process in /proc
 * pidGuess: the guess for which process is the coap process*/
int findCoapPid(string binName, int maxTries = 8){
    //cout << "Trying to find Coap binary, searching through /proc/\n";
    int retries = 0;
    long sleepTimeMs = 100;
    long backOffMs = 100;
    auto start = chrono::system_clock::now();
    do{
        for(fsys::directory_entry direntry: fsys::directory_iterator("/proc/")){
            if(!fsys::is_directory(direntry)){
                continue;
            }

            if(isProcNamed((string)(direntry.path().filename()), binName)){
                auto end = chrono::system_clock::now();
                chrono::duration<double> d = end-start;
                //cout << "Elapsed time: " << d.count()<< "\n";
                return stol((string)(direntry.path().filename()));
            }
        }

        //cout << "Could not find process named: " << binName << ", Retrying in "<< sleepTimeMs <<"ms\n";
        sleepMs(sleepTimeMs);
        sleepTimeMs += backOffMs;
    }while(retries++ < maxTries);
    return -1;
}


/* Forks a child process that starts the CoAP binary using dynamorio  
 * Returns the pid of the coap server*/
int runDynamorio(){
    string exe, logDir, dumpOpt, moduleStr;
    if(configs.ready){
        exe = configs.coapExeCmd;
        logDir = configs.logDir;
        dumpOpt = configs.dumpOpt;
        moduleStr = configs.moduleStr;
    }else{
        exe = "../servers/microcoap/coap";
        logDir = "../servers/coveragelogs";
        dumpOpt = "-dump_text";
        moduleStr = "microcoap";
    }
    string command = "../dynamorio/build/bin64/drrun -t drcov -logdir ";
    command.append(logDir).append(" ").append(dumpOpt).append(" -- ").append(exe);

    int pid = fork();
    if(pid == 0){
        execl("/bin/sh", "sh", "-c", command.c_str(), (char*) 0);
    }else{
        //cout << "I am parent, child is: " << pid+1 << "\n";
    }

    int coapPid = findCoapPid(configs.coapBinName);
    
    return coapPid;
}

/* Kills the process and collects the zombie */
int killProc(int procId){
    kill(procId, SIGTERM);
    if(configs.moduleStr.compare("libcoap") == 0){
        system("killall coap-server");
    }
    sleepMs(100);
    waitpid(procId, 0, WNOHANG);
    waitpid(0, 0, WNOHANG);
    //cout << "Killed process: " << procId << "\n";
    return 0;
}

/* Creates a zero initiated string of the given number*/
string getStringZeroInit(int num, int size){
    string s = to_string(num);
    string retStr = "";
    int fill = size - s.length();
    while(fill-- > 0){
        retStr.append("0");
    }
    retStr.append(s);
    return retStr;
}

/* Calculates the pathname for the log. The naming convention is chosen by Dynamorio. 
 * Logs are identified with the PID of the ran process and a redundancy value if two 
 * logs with same process ID are exist */
string calcLogPath(int coapPid){
    string coapPidStr = getStringZeroInit(coapPid,5); //Log files are created with zero init
    int redundancy = 0;
    string path, fileName;
    do{
        ////Follows structure: <tool (drcov)>.<binary (coap)>.<pid (5 digits)>.<redundancy (4 digits)>.proc.log
        fileName = stringConcat({"drcov", configs.coapBinName, coapPidStr, getStringZeroInit(redundancy,4), "proc", "log"}, ".");
        path = stringConcat({configs.logDir, fileName});

        if(!fsys::exists(path)){
            //If the path does not exist, it means that the previous redundancy value is the latest
            //created by Dynamorio, and is thus the current log
            redundancy--;
            fileName = stringConcat({"drcov", configs.coapBinName, coapPidStr, getStringZeroInit(redundancy,4), "proc", "log"}, ".");
            path = stringConcat({configs.logDir, fileName});
            return path;
        }
        redundancy++;
    }while(redundancy < 10000); //4 digit redundancy available

    cout << "Unable to locate the intended log file for Dynamorio.\nReading: " << path << "\n"; 
    return path;
}

/* Returns the fitness for the CoAP process id  */
int calcFitness(int coapPid){
    string path = calcLogPath(coapPid);

    string moduleStr;
    if(!configs.ready){
        cout << "Config was not ready. Verify that the config file exist and has the proper format. Exiting \n";
        exit(0);
    }else{
        moduleStr = configs.moduleStr;
    }

    cout << path << "\n";
    int fitness = parseDrcov(path, moduleStr);

    return fitness;
}

/* Placeholder function that is used to send network packets according to input */
void waitForPackets(){
    string tmp;
    cout << "Waiting with CoAP running. Enter any character to kill CoAP and retrieve fitness: \n";
    cout << "> ";
    while(cin >> tmp && tmp.compare("done") != 0){
        if(tmp.compare("1") == 0){
            vector<std::byte> vec = 
            {(std::byte)0x40, (std::byte)0x01, (std::byte)0x73, (std::byte)0x6A, (std::byte)0x39, (std::byte)0x6C, (std::byte)0x6F, (std::byte)0x63, (std::byte)0x61, (std::byte)0x6C, (std::byte)0x68, (std::byte)0x6F, (std::byte)0x73, (std::byte)0x74, (std::byte)0x8B, (std::byte)0x2E, (std::byte)0x77, (std::byte)0x65, (std::byte)0x6C, (std::byte)0x6C, (std::byte)0x2D, (std::byte)0x6B, (std::byte)0x6E, (std::byte)0x6F, (std::byte)0x77, (std::byte)0x6E, (std::byte)0x04, (std::byte)0x63, (std::byte)0x6F, (std::byte)0x72, (std::byte)0x65};
            netw::coap_socket s = netw::getCoapSocket("127.0.0.1");
            s.sendUDP(vec);
            s.sendUDP(vec);
            s.recUDP(1);
            s.close_socket();
        }else if(tmp.compare("2") == 0){
        }else{
        }
        cout << "> ";
    }
}

void sendPacket(std::vector<std::byte> vec){
    netw::coap_socket s = netw::getCoapSocket("127.0.0.1");
    s.sendUDP(vec);
    s.recUDP(1);
    s.close_socket();
}

bool checkAliveness(){
    netw::coap_socket s = netw::getCoapSocket("127.0.0.1");
    s.sendUDP(packPacket(wkcore_packet));
    bool alive = s.recUDP(1);
    s.close_socket();
    return alive;
}


/* Performs all the actions to get the code coverage of a sessions (string of packets)  */
int getSessionCodeCoverage(std::vector<std::vector<std::byte>>& cpacks){
    int coapPid = runDynamorio();
    if(coapPid < 0){
        cout << "Could not run dynamorio properly\n";
    }
    for(auto& cpack: cpacks){
        sendPacket(cpack);
        sleepMs(15);
    }

    bool alive = checkAliveness();
    if(!alive){
        //LOG PACKETS
        log_packets(cpacks);
        return -1;
    }

    killProc(coapPid);

    int sleepTime = 100;
    sleepMs(sleepTime);

    int fitness = calcFitness(coapPid);
    cleanLogDir();

    return fitness;
}
int getSessionCodeCoverage(std::vector<coap_packet>& cpacks){
    std::vector<std::vector<std::byte>> packed_cpacks;
    for(coap_packet cpack: cpacks){
        std::vector<std::byte> packed = packPacket(cpack);
        packed_cpacks.push_back(packed);
    }
    return getSessionCodeCoverage(packed_cpacks);
}

int startRecPoolCoverage(bool reset = 1){
    poolCov.active = 1;
    if(reset){
        poolCov.vec.clear();
    }
    return 0;
}

int endRecPoolCoverage(){
    poolCov.active = 0;
    int poolFitness = poolCov.vec.size();
    poolCov.vec.clear();
    return poolFitness;
}


#endif
