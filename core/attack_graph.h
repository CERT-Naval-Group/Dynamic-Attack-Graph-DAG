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


#ifndef ATTACK_GRAPH_H
#define ATTACK_GRAPH_H

#define DESCRIPTION 0
#define DEPENDENCIES 1
#define CHILDREN 2
#define TYPE 3
#define RULE 0
#define LEAF 1
#define STATE 2
#define CONDITION 3
#define NBDEP 4
#define NBCHILD 5
#define TIMER 6
#define PRED 7


#include <iostream>
#include <stdlib.h>
#include <fstream>
#include <vector>
#include "boost/date_time/posix_time/posix_time.hpp"
#include <boost/algorithm/string.hpp>
#include <map>
#include <chrono>

#include "json.hpp"

#include "rule_functions.h"

using namespace std;
using json = nlohmann::json;


struct Timer{
    Timer(unsigned long r1, unsigned long r2, unsigned char type1, float* params1, unsigned int nb_params1, unsigned char type2, float* params2, unsigned int nb_params2);

    unsigned long r1;
    unsigned long r2;
    unsigned char type1;
    float* params1;
    unsigned int nb_params1;
    unsigned char type2;
    float* params2;
    unsigned int nb_params2;
};

struct Prob{
    unsigned long r1;
    unsigned long r2;
    float prob;
};

struct Pred{
    string* params;
    unsigned int nb_params;
    Prob* timed_probs;
    unsigned int nb_probs;
};

struct Node{
    string description;
    unsigned int* dependencies;
    unsigned int* children;
    unsigned char type;
    unsigned int nb_dep;
    unsigned int nb_child;
    Timer* timers;
    unsigned int nb_timers;
    Prob* timed_preds;
    unsigned int nb_timed_preds;

};

struct Param{
	Pred pred;
	map<string, Param> params_list;
};

struct Literal{
	map<string, Pred> pred_list;
	map<string, Param> params_list;
};


class AttackGraph{

    private:
        json config;
        map<string, void (*)(void** params)> timer_functions;
        unsigned int graph_size;
        string vertices_file_path;
        string arcs_file_path;
        unsigned int* rule_nodes;
        unsigned int* fact_nodes;
        unsigned int nb_rule_nodes;
        unsigned int nb_fact_nodes;

        void buildTimers(unsigned int node_id);
        void buildTimedPredicats(unsigned int node_id, map<string, Literal> &);
        bool matchPred(string params1, string* params2, unsigned int nb_params2);
        unsigned int datetimeToRound();
        void timedInputParser(map<string, Literal>&);


    public:
        Node* ag;
        AttackGraph();
        friend ostream& operator<<(ostream& os, const AttackGraph& ag);
        void setConfigFile(json config);
        void setGraphSize();
        unsigned int getGraphSize();
        void buildGraph();
        void setRuleFunction(string rule_name, void (*setTimer)(void** params));
        string getTimeUnit();
        unsigned int getNbRuleNodes();
        unsigned int getNbFactNodes();
        unsigned int* getRuleNodes();
        unsigned int* getFactNodes();

};


#endif
