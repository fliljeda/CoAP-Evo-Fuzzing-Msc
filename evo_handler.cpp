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

bool rollOnPercentage(int chance){
    return (rand()%100) < chance;
}


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

/* Assigns [0-max) on parameters but not the same value */
void assignTwoDifferentRandom(int& a, int& b, int max){
    if(max == 1){
        a = 0;
        b = 0;
        return;
    }
    a = rand()%max;
    while((b = rand()%max) == a);
}

void measureFitness(std::vector<pool_t>& pools){
    for(size_t i = 0; i < pools.size(); i++){
        measureFitness(pools[i]);
    }
    sort(pools.begin(), pools.end(), [](const pool_t& a,const pool_t& b){
        return a.pool_fitness > b.pool_fitness;
    });
}

/* Removes (not the most fit) a random session and generates a session and addds to pool*/
void evolvePoolMutation(std::vector<pool_t>& pools){
    for(pool_t& p: pools){
        poolMutation(p.sessions, PACKETS_N);
    }
}

/* Crossover the pools. Assumes a fitness sorted pool list */
void evolvePoolCrossover(std::vector<pool_t>& pools){
    std::vector<pool_t> newPools;

    newPools.push_back(pools[0]);

    for(size_t j = 1; j < POOLS_N; j++){
        bool topHalf = rollOnPercentage(70);
        int a,b;
        assignTwoDifferentRandom(a,b, topHalf ? pools.size()/2 : pools.size());
        pool_t tmp_pool;
        tmp_pool.sessions = poolCrossover(pools[a].sessions, pools[b].sessions, rand()%POOLS_N);
        newPools.push_back(tmp_pool);
    }

    pools = newPools;
}

/* Chooses two different packets from each session to do a mutation on */
void evolveSessionMutation(std::vector<pool_t>& pools){
    for(pool_t& p: pools){
        for(auto& session: p.sessions){
            int a,b;
            //account for not changing most fit session
            int maxRoll = SESSIONS_N-1;
            assignTwoDifferentRandom(a,b, maxRoll);
            a++; b++;
            sessionMutation(session, a, b);
        }
    }
}

/* Assumes all sessions are sorted according to fitness */
/* For each pool's session we copy over the most fit into the new
 * sessions list, then continuosly adds a crossoversection until
 * we fill up the sessions */
void evolveSessionCrossover(std::vector<pool_t>& pools){
    for(pool_t& p: pools){
        std::vector<std::vector<coap_packet>> tmp;
        tmp.push_back(p.sessions[0]);
        for(size_t j = 1; j < SESSIONS_N; j++){
            bool topHalf = rollOnPercentage(70);
            int a,b;
            assignTwoDifferentRandom(a,b, topHalf ? p.sessions.size()/2 : p.sessions.size());
            tmp.push_back(sessionCrossover(p.sessions[a], p.sessions[b], rand()%SESSIONS_N));
        }
        p.sessions = tmp;
    }
}

/* Performs an evolution step on the pools. Assumes a sorted list with the smallest
 * index being the most fit */
void evolve(std::vector<pool_t>& pools){
    //Session crossover happens every generation
    //
    evolveSessionCrossover(pools);
    
    bool session_mutation_b = rollOnPercentage(50);
    if(session_mutation_b){
        evolveSessionMutation(pools);
    }

    bool pool_crossover_b = rollOnPercentage(25);
    if(pool_crossover_b){
        evolvePoolCrossover(pools);
    }

    bool pool_mutation_b = rollOnPercentage(25);
    if(pool_mutation_b){
        evolvePoolMutation(pools);
    }

    
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
