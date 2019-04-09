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
#include "coap_mutations.cpp"
#include "server_handler.cpp"
#include "fuzzer.cpp"

#ifndef EVO_HANDLER
#define EVO_HANDLER

const size_t POOLS_N = 10;
const size_t SESSIONS_N = 10;
const size_t PACKETS_N = 10;


struct pool_t{
    std::vector<std::vector<coap_packet>> sessions;
    std::vector<int> session_fitness;
    int pool_fitness = 0;

    /* Sort sessions according to the session fitness vector in descending order
     * TODO Refactor sessions to struct and sort directly*/
    void sortByFitness(){
        for(size_t i = 0; i < sessions.size(); i++){
            int max_ind = i;
            for(size_t j = i; j < sessions.size(); j++){
                if(session_fitness[j] > session_fitness[max_ind]){
                    max_ind = j;
                }
            }
            auto tmp = sessions[i];
            sessions[i] = sessions[max_ind];
            sessions[max_ind] = tmp;

            int tmp_n = session_fitness[i];
            session_fitness[i] = session_fitness[max_ind];
            session_fitness[max_ind] = tmp_n;
        }
    }
};


void measureFitness(pool_t& pool){
    startRecPoolCoverage();

    for(size_t i = 0; i < pool.sessions.size(); i++){
        int cc = getSessionCodeCoverage(pool.sessions[i]);
        pool.session_fitness[i] = cc;
    }
    pool.pool_fitness = endRecPoolCoverage();
    pool.sortByFitness();
}

void measureFitness(std::vector<pool_t>& pools){
    for(size_t i = 0; i < pools.size(); i++){
        measureFitness(pools[i]);
    }
    sort(pools.begin(), pools.end(), [](const pool_t& a,const pool_t& b){
        return a.pool_fitness > b.pool_fitness;
    });
}

void evolve(std::vector<pool_t> pools){
    //Select
}

void run(){
    std::vector<pool_t> pools(POOLS_N);
    for(size_t i = 0; i < pools.size(); i++){
        pools[i].session_fitness.resize(SESSIONS_N);
        pools[i].sessions = generatePool(SESSIONS_N, PACKETS_N);
    }

    int generation = 0;
    while(1){
        measureFitness(pools);
        evolve(pools);
        generation++;
    }

}

#endif
