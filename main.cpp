#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <sys/wait.h>

using namespace std;

struct configuration{
    bool ready;
    string coapPath;
    string logDir;
    string dumpOpt;
    string coapBinName;
} configs;

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
        }else if(option.compare("dumpopt") == 0){
            configs.dumpOpt = value;
        }else if(option.compare("coapbinname") == 0){
            configs.coapBinName = value;
        }
    }
    configs.ready = 1;
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
//Searches the table for lins that contain the name
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
vector<basic_block> calcUniqueBlocks(ifstream& fs, int selectedMod){
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

    vector<basic_block> uniqueBlocks = calcUniqueBlocks(fs,selectedMod);
    return uniqueBlocks;
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
    
    //TODO make coap server process id more robust (it is +1 because sh creates a new process)
    return pid+1;
}

/* Kills the process and collects the zombie */
int killProc(int procId){
    system(string("kill ").append(to_string(procId)).c_str());
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
    string path = string("../servers/coveragelogs/").append("drcov.coap.").append(coapPidStr).append(".0000.proc.log");

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
    cout << "Waiting for CoAP to run. Enter any character to continue: ";
    cin >> tmp;
    killProc(coapPid);

    int sleepTime = 1;
    cout << "Sleeping " << sleepTime << " seconds to allow dynamorio to write results\n";
    sleep(sleepTime);

    calcFitness(coapPid);

    return 0;
}

