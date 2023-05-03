//  -------- copyright holders --------

//  This file is part of Dynamic Attack Graph GEneRator - DAGGER.

//  Dynamic Attack Graph GEneRator - DAGGER is free software; you can redistribute it and/or modify
//  it under the terms of the GNU Lesser General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.

//  Dynamic Attack Graph GEneRator - DAGGER is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Lesser General Public License for more details.

//  You should have received a copy of the GNU Lesser General Public License
//  along with Dynamic Attack Graph GEneRator - DAGGER; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

#pragma once
#ifndef TAG_H
#define TAG_H

#include <random>
#include <iostream>
#include <stdlib.h>
#include <fstream>
#include <thread>
#include <unistd.h>
#include <chrono>
#include <sys/types.h>
#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <time.h>
#include <tgmath.h>

#include "attack_graph.h"
#include "json.hpp"
#include "rule_functions.h"
#include "log.h"


using namespace std;
using json = nlohmann::json;


struct TimerValue{
    unsigned int timer;
    bool flag;
    unsigned int start_round;
    unsigned int end_round;
};


struct Dep{
    unsigned int nb_dep;
    bool flag;
};


class TAG{
    private:
        AttackGraph ag;
        unsigned int** simulation_res;
        string config_file_path;
        json config;
        unsigned int start_round;
        unsigned int end_round;
        unsigned int nb_round;
        unsigned int step;

        void parseConfigFile();
    public:
        TAG(char* config_file_path);
        void run();
};

void launchSimulation(AttackGraph* ag, unsigned int** simulation_res, std::mutex** round_locks, unsigned int start_round, unsigned int end_round, unsigned int nb_round, unsigned int step, string working_dir);
void computeNode(unsigned int node_id, AttackGraph* ag, unsigned int* current_round, unsigned int* past_round, unsigned int round, unsigned int step, Prob* currents_prob, Dep* dependencies_counter, TimerValue* timers, bool direct_call);
void checkForChildrenToCompute(unsigned int node_id, AttackGraph* ag, unsigned int* current_round, unsigned int* past_round, unsigned int round, unsigned int step, Prob* currents_prob, Dep* dependencies_counter, TimerValue* timers);
float getProb(unsigned int node_id, unsigned int round, AttackGraph* ag, Prob* currents_prob);
bool testTimer(unsigned int id, unsigned int round, unsigned int step, TimerValue* timer, AttackGraph* ag);
void genTimer(unsigned int id, unsigned int round, TimerValue* timer, AttackGraph* ag);
unsigned int genRandom(unsigned char type, float* params, unsigned int nb_params, string time_unit);
unsigned int convertTimer(float timer, string time_unit);
bool checkLeafProbAlreadyExists(unsigned int node_id, unsigned int round, AttackGraph* ag, Prob* currents_prob);
unsigned int roundToTabIndex(unsigned int round, unsigned int step);

#endif
