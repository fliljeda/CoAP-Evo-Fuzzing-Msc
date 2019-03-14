#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <regex>
#include <sys/wait.h>
#include <experimental/filesystem>

using namespace std;
namespace fsys = std::experimental::filesystem;

struct configuration{
    bool ready;
    string coapPath;
    string logDir;
    string dumpOpt;
    string coapBinName;
} configs;

/* Returns  */
string getNowDateString(){
        std::time_t now_c = time(nullptr);
        char time[20];
        strftime(time, sizeof(time), "%F", localtime(&now_c));
        return string(time);
}

/* Checks the log directory if there is a directory in it for today's log
 * If so: append that directory to the logdir path
 * If not: create the directory and append it to path*/
bool setCurrentLogdir(string& logDir){
    string dateStr = getNowDateString();
    bool dirExists = 0;
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
    string newPath = logDir.append("/").append(dateStr).append("/");
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
        if(option.compare("coappath") == 0){
            configs.coapPath = value;
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
        }
    }
    configs.ready = 1;
}

/* Sleep for @param milliseconds*/
void mySleepMilli(long milliseconds){
    struct timespec tim1, tim2;
    tim1.tv_sec = 0;
    tim1.tv_nsec = ((long)milliseconds) * 1000000L;
    
    nanosleep(&tim1, &tim2);

}


struct basic_block {
    size_t number;
    int occurrances = 0;
};


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

//Find module ID of the targetted application
//Searches the table for lines that contain the name
int findMod(ifstream &fs, string binName){
    string str;
    int count;
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
        if(str.rfind(binName) != string::npos){
            int start = str.find(',')+1;
            int end = str.find(',', start);
            string modField = str.substr(start, end-start);
            int modId = stoul(modField, nullptr, 10);
            return modId;
        }
    }
    return -1;
}

//Parses the BB lines of the file. Adding unique BB as elements of the returned vector
vector<basic_block> calcBasicBlocks(ifstream& fs, int selectedMod){
    string str = "";
    int numOfChosenBB = 0;
    int numOfBB = 0;
    vector<basic_block> v;
    while(getline(fs,str)){

        if(str.rfind("BB Table", 0) == 0){ //if found word is at beginning
            regex rgx("\\d+");
            smatch match;
            if(regex_search(str, match ,rgx)){
                numOfBB = stoul(match[0], nullptr, 10);
            }

        }
        
        if(str.rfind("module", 0) == 0){ //if found word is at beginning
            size_t start = str.find('[')+1;
            size_t end = str.find(']', start);
            if(start == string::npos || end == string::npos){
                continue;
            }
            string moduleStr = str.substr(start, end-start);
            int module = stoul(moduleStr, nullptr, 10);

            if(module == selectedMod || selectedMod == -1){
                numOfChosenBB++;
                string sub = str.substr(13,18); //Fixed length 
                size_t num = stoul(sub, nullptr, 16);

                addBB(num, v);
            }
        }
    }
    cout << "BB Total: " <<  numOfBB  << "\n";
    cout << "Chosen BB: " << numOfChosenBB << "\n";
    cout << "Chosen unique BB: "  <<v.size() << "\n";
    return v;
}

vector<basic_block> parseDrcov(string pathToFile, string binName){

    ifstream fs(pathToFile);

    //If we only want to parse from a selected mod§
    bool isModSelected = binName.empty() ? 0 : 1; 
    int selectedMod;
    if(isModSelected){
        selectedMod = findMod(fs, binName);
        if(selectedMod == -1){
            cout << "COULD NOT FIND THE MODULE CONTAINING: " << binName << "\n";
            cout << "CONTINUING CALCULATING ALL: " << binName << "\n";
        }
        cout << selectedMod << "\n";
    }

    vector<basic_block> uniqueBlocks = calcBasicBlocks(fs,selectedMod);
    return uniqueBlocks;
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
int findCoapPid(int pidGuess, int guessTries = 3, int guessSleepMilli = 5){
    for(int i = 0; i < guessTries; i++){
        cout << "Try" << "\n";
        if(isProcNamed(pidGuess, "coap")){
            return pidGuess;
        }
        mySleepMilli(guessSleepMilli);
    }

    cout << "Process "<< pidGuess << " was not the coap process, searching through /proc/\n";
    for(fsys::directory_entry direntry: fsys::directory_iterator("/proc/")){
        if(!fsys::is_directory(direntry)){
            continue;
        }
        if(isProcNamed((string)(direntry.path().filename()), "coap")){
            return stol((string)(direntry.path().filename()));
        }
    }
    return -1;
}

/* Forks a child process that starts the CoAP binary using dynamorio  
 * Returns the pid of the coap server*/
int runDynamorio(){
    string exe, logDir, dumpOpt;
    if(configs.ready){
        exe = configs.coapPath;
        logDir = configs.logDir;
        dumpOpt = configs.dumpOpt;
    }else{
        exe = "../servers/microcoap/coap";
        logDir = "../servers/coveragelogs";
        dumpOpt = "-dump_text";
    }
    string command = "../dynamorio/build/bin64/drrun -t drcov -logdir ";
    command.append(logDir).append(" ").append(dumpOpt).append(" -- ").append(exe);

    int pid = fork();
    if(pid == 0){
        execl("/bin/sh", "sh", "-c", command.c_str(), (char*) 0);
    }else{
        cout << "I am parent, child is: " << pid+1 << "\n";
    }

    int coapPid = findCoapPid(pid+1);
    cout << "Coap PID: " << coapPid << "\n";

    return pid+1;
}

/* Kills the process and collects the zombie */
int killProc(int procId){
    kill(procId, SIGTERM);
    waitpid(procId, 0, WNOHANG);
    cout << "Killed process: " << procId << "\n";
    return 0;
}

/* Utility function to get the pid format of the log names. 5 characters with leading zeroes*/
string getLogPidString(int pid){
    string s = to_string(pid);
    string retStr = "";
    int fill = 5 - s.length();
    while(fill-- > 0){
        retStr.append("0");
    }
    retStr.append(s);
    return retStr;
}

void calcFitness(int coapPid){
    string coapPidStr = getLogPidString(coapPid);
    string redundancy = "0000";
    string path = string(configs.logDir).append("drcov.coap.").append(coapPidStr)
        .append(".").append(redundancy).append(".proc.log");

    string binName;
    if(!configs.ready){
        cout << "Config was not ready. Verify that the config file exist and has the proper format. Exiting \n";
        exit(0);
    }else{
        binName = configs.coapBinName;
    }

    cout << path << "\n";
    parseDrcov(path, binName);

}


int main(int argc, char *argv[]){

    readConfig();

    int coapPid = runDynamorio();
    if(coapPid < 0){
        cout << "Could not run dynamorio properly\n";
    }
    string tmp;
    cout << "Waiting with CoAP running. Enter any character to kill CoAP and retrieve fitness: ";
    cin >> tmp;
    killProc(coapPid);

    int sleepTime = 1;
    cout << "Sleeping " << sleepTime << " seconds to allow dynamorio to write results\n";
    sleep(sleepTime);

    calcFitness(coapPid);

    return 0;
}

