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

#include "tag.h"



TAG::TAG(char* config_file_path){
    this->config_file_path = config_file_path;
    this->parseConfigFile();
    this->ag.setConfigFile(this->config);
    this->ag.setGraphSize();
    this->ag.setRuleFunction("default", defaultRuleFunction);
    this->ag.setRuleFunction("remote exploit of a server program", vulnExploitRuleFunction);
    this->ag.buildGraph();
    
    
    openLogFile((string) this->config["working_dir"] + "log/dag.log");


    ptime start_date(boost::posix_time::time_from_string(this->config["start"]));
    ptime end_date(boost::posix_time::time_from_string(this->config["end"]));
    this->nb_round = datesToRoundDuration(start_date, end_date, this->config["timeUnit"]);
    this->start_round = dateToRound(start_date, this->config["timeUnit"]);
    this->end_round = dateToRound(end_date, this->config["timeUnit"]);


    if(this->config["timeUnit"] == "second"){
        this->step = 1;
    }else if(this->config["timeUnit"] == "minute"){
        this->step = 60;
    }else if(this->config["timeUnit"] == "hour"){
        this->step = 3600;
    }else if(this->config["timeUnit"] == "day"){
        this->step = 86400;
    }else{
        cout << "Wrong time unit!" << endl;
        exit(1);
    }


    this->simulation_res = (unsigned int**) calloc(roundToTabIndex(this->nb_round, this->step) + 1, sizeof(unsigned int*));
    for(unsigned int i = 0; i < roundToTabIndex(this->nb_round, this->step) + 1; i++){
        this->simulation_res[i] = (unsigned int*) calloc(this->ag.getGraphSize() + 1, sizeof(unsigned int));
        for(unsigned int j = 0; j < this->ag.getGraphSize() + 1; j++){
            this->simulation_res[i][j] = 0;
        }
    }


    cout << "Size of graph : " << this->ag.getGraphSize() << endl;
    
    writeLog("TAG : End constructor");
}


void TAG::parseConfigFile(){
    string json_data = "";
    string buffer;
    ifstream file(this->config_file_path);

    while (getline (file, buffer)) {
        json_data += buffer;
    }

    this->config = json::parse(json_data);
    file.close();
}


void TAG::run(){
    cout << "Simulation is running..." << endl;
    writeLog("TAG : Start run");

    auto start = std::chrono::high_resolution_clock::now();

    std::mutex** round_locks = (std::mutex**) calloc(roundToTabIndex(this->nb_round, this->step) + 1, sizeof(std::mutex*));

    for(unsigned int i = 0; i < roundToTabIndex(this->nb_round, this->step) + 1; i++){
        round_locks[i] = (std::mutex*) calloc(1, sizeof(std::mutex));
        new (round_locks[i]) std::mutex{};
    }


    unsigned int nb_cpu_core = sysconf(_SC_NPROCESSORS_ONLN);
    boost::asio::thread_pool workers(nb_cpu_core);

    unsigned int nb_simulation = this->config["nbSimulations"];
    for(unsigned int i = 0; i < nb_simulation; i++){
    	writeLog("TAG : Start new simulation " + std::to_string(i));
        boost::asio::post(workers, std::bind(launchSimulation, &this->ag, this->simulation_res, round_locks, this->start_round, this->end_round, this->nb_round, this->step, this->config["working_dir"]));
    }

    workers.join();
    
    writeLog("TAG : Finished all simulations");

    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    float duration_time = (float) duration.count() / 1000.0;
    cout << "Execution time of the simulation : " << duration_time << " seconds" << endl;


    ofstream res_file((string)this->config["working_dir"] + "sim_res/res.txt");

	writeLog("TAG : Writing data to file sim_res.txt");
    for(unsigned int i = 0; i < roundToTabIndex(this->nb_round, this->step) + 1; i++){
    	unsigned int j;
        for(j = 1; j < this->ag.getGraphSize(); j++){
            res_file << (float) ((float)this->simulation_res[i][j] / (float)nb_simulation) << ",";
        }
        res_file << (float) ((float)this->simulation_res[i][j] / (float)nb_simulation);
        res_file << endl;
    }
	
	closeLogFile();
    res_file.close();
}


void launchSimulation(AttackGraph* ag, unsigned int** simulation_res, std::mutex** round_locks, unsigned int start_round, unsigned int end_round, unsigned int nb_round, unsigned int step, string working_dir){
    unsigned int* buffer_round = NULL;

    boost::uuids::uuid uuid = boost::uuids::random_generator()();
    ofstream res_file(working_dir + "output/" + boost::uuids::to_string(uuid) + ".txt");
	
	string pid = std::to_string(gettid());
	writeLog("Thread " + pid + " : Start");
	writeLog("Thread " + pid + " : Initialization");
	
	
    //Init prob list for fact nodes
    Prob* currents_prob = (Prob*) calloc(ag->getGraphSize() + 1, sizeof(Prob));
    for(unsigned int i = 0; i < ag->getGraphSize() + 1; i++){
        currents_prob[i].r1 = 0;
        currents_prob[i].r2 = 0;
        currents_prob[i].prob = -1;
    }


    //Init dependencies counter
    Dep* dependencies_counter = (Dep*) calloc(ag->getGraphSize() + 1, sizeof(Dep));
    for(unsigned int i = 0; i < ag->getGraphSize() + 1; i++){
        dependencies_counter[i].nb_dep = 0;
        dependencies_counter[i].flag = false;
    }


    //Init current_round and past_round
    unsigned int* current_round = (unsigned int*) calloc(ag->getGraphSize() + 1, sizeof(unsigned int));
    unsigned int* past_round = (unsigned int*) calloc(ag->getGraphSize() + 1, sizeof(unsigned int));
    for(unsigned int i = 0; i < ag->getGraphSize() + 1; i++){
        current_round[i] = 0;
        past_round[i] = 0;
    }


    //Init timers
    TimerValue* timers = (TimerValue*) calloc(ag->getGraphSize() + 1, sizeof(TimerValue));
    for(unsigned int i = 1; i < ag->getGraphSize() + 1; i++){
        genTimer(i, start_round, timers, ag);
    }


	writeLog("Thread " + pid + " : Start the simulation");
    for(unsigned int i = 0; i < nb_round; i += step){

        //Reinit dependencies counter
        for(unsigned int j = 1; j < ag->getGraphSize() + 1; j++){
            dependencies_counter[j].nb_dep = ag->ag[j].nb_dep;
            dependencies_counter[j].flag = false;
        }


        //Compute each literal nodes
        for(unsigned int j = 0; j < ag->getNbFactNodes(); j++){
            //if(j == 6 && (start_round + i == 1611100800)){
            	//cout << "CALL computeNode from the sim function for the node 6 at round 1611100800" << endl;
            //}
            computeNode(ag->getFactNodes()[j], ag, current_round, past_round, start_round + i, step, currents_prob, dependencies_counter, timers, true);
        }


        //Add current_round to simulation_res
        round_locks[roundToTabIndex(i, step)][0].lock();
        unsigned int k;
        for(k = 1; k < ag->getGraphSize(); k++){
        
            simulation_res[roundToTabIndex(i, step)][k] += current_round[k];
            res_file << current_round[k] << ",";
        }
        simulation_res[roundToTabIndex(i, step)][k] += current_round[k];
        res_file << current_round[k];
        res_file << endl;
        round_locks[roundToTabIndex(i, step)][0].unlock();


        //Switch current_round and past_round
        buffer_round = past_round;
        past_round = current_round;
        current_round = buffer_round;

        //Reinit current_round
        for(unsigned int j = 0; j < ag->getGraphSize() + 1; j++){
            current_round[j] = 0;
        }
    }
    
    
    writeLog("Thread " + pid + " : Free memory");
    
    
    //Free prob list for fact nodes
    free(currents_prob);
    
    
    //Free dependencies counter
   	free(dependencies_counter);
    
    
    //Free current_round and past_round
    free(current_round);
    free(past_round);
    
    
    //Free timers
    free(timers);
    
    
    writeLog("Thread " + pid + " : End the simulation");
}


void computeNode(unsigned int node_id, AttackGraph* ag, unsigned int* current_round, unsigned int* past_round, unsigned int round, unsigned int step, Prob* currents_prob, Dep* dependencies_counter, TimerValue* timers, bool direct_call){
    float prob;
    bool flag = true;
    std::random_device rng;
    std::default_random_engine generator(rng());

    // IF a STATE node with an assigned prob is traversed a first time by a direct call of launchSimulation, a recursive second call has to be blocked in order to prevent the attribution of the value of past_round with function checkLeafProbAlreadyExists
    if(ag->ag[node_id].type == STATE && dependencies_counter[node_id].nb_dep == 0 && currents_prob[node_id].prob != -1){
    	return;
    }
    
    // IF a node has already be traversed recursivly, it is not necessary to compute it a second time by a direct call of launchSimulation
    if(ag->ag[node_id].type != LEAF && dependencies_counter[node_id].nb_dep == 0 && direct_call == true){
    	return;
    }

    if(ag->ag[node_id].type == LEAF){

        if(checkLeafProbAlreadyExists(node_id, round, ag, currents_prob)){
            current_round[node_id] = past_round[node_id];
        }else{
            prob = getProb(node_id, round, ag, currents_prob);
            std::uniform_real_distribution<float> distribution(0,1);

            if(prob == 1 || prob > distribution(generator)){
                current_round[node_id] = 1;
            }else{
                current_round[node_id] = 0;
            }
        }


    }else if(ag->ag[node_id].type == STATE || ag->ag[node_id].type == CONDITION){
        
        if(checkLeafProbAlreadyExists(node_id, round, ag, currents_prob)){
            current_round[node_id] = past_round[node_id];
        } else if((prob = getProb(node_id, round, ag, currents_prob)) != -1){
            std::uniform_real_distribution<float> distribution(0,1);
            
            if(prob == 1 || prob > distribution(generator)){
                current_round[node_id] = 1;
            }else{
                current_round[node_id] = 0;
            }
        } else if(ag->ag[node_id].type == STATE && past_round[node_id] == 1){        
            current_round[node_id] = 1;


        } else if(ag->ag[node_id].type == STATE || ag->ag[node_id].type == CONDITION){
            if(dependencies_counter[node_id].flag == true){
                current_round[node_id] = 1;
            }else if(dependencies_counter[node_id].nb_dep == 0){
                current_round[node_id] = 0;
            } else{
                flag = false;
            }
        }


    }else if(ag->ag[node_id].type == RULE){
        if(dependencies_counter[node_id].flag == true){
            if(testTimer(node_id, round, step, timers, ag)){
                current_round[node_id] = 1;
            } else{
                current_round[node_id] = 0;
            }
        }else{
            current_round[node_id] = 0;
        }


    }else{
        flag = false;
    }

    if(flag){
        checkForChildrenToCompute(node_id, ag, current_round, past_round, round, step, currents_prob, dependencies_counter, timers);
    }
}


void checkForChildrenToCompute(unsigned int node_id, AttackGraph* ag, unsigned int* current_round, unsigned int* past_round, unsigned int round, unsigned int step, Prob* currents_prob, Dep* dependencies_counter, TimerValue* timers){

    if(ag->ag[node_id].type == RULE){
        unsigned int child = ag->ag[node_id].children[0];
        
        if(dependencies_counter[child].nb_dep > 0){
            if(current_round[node_id] == 0){
                dependencies_counter[child].nb_dep -= 1;
                if(dependencies_counter[child].nb_dep == 0){
                    dependencies_counter[child].flag = false;
                    computeNode(child, ag, current_round, past_round, round, step, currents_prob, dependencies_counter, timers, false);
                }
            } else{
                dependencies_counter[child].nb_dep = 0;
                dependencies_counter[child].flag = true;
                computeNode(child, ag, current_round, past_round, round, step, currents_prob, dependencies_counter, timers, false);
            }
        }
    }else{
        unsigned int nb_children = ag->ag[node_id].nb_child;
        unsigned int* children = ag->ag[node_id].children;
        if(current_round[node_id] == 0){
            for(unsigned int i = 0; i < nb_children; i++){
                if(dependencies_counter[children[i]].nb_dep != 0){
                    dependencies_counter[children[i]].nb_dep = 0;
                    dependencies_counter[children[i]].flag = false;
                    computeNode(children[i], ag, current_round, past_round, round, step, currents_prob, dependencies_counter, timers, false);
                }
            }
        } else{
            for(unsigned int i = 0; i < nb_children; i++){
                if(dependencies_counter[children[i]].nb_dep != 0){
                    dependencies_counter[children[i]].nb_dep -= 1;
                    if(dependencies_counter[children[i]].nb_dep == 0){
                        dependencies_counter[children[i]].flag = true;
                        computeNode(children[i], ag, current_round, past_round, round, step, currents_prob, dependencies_counter, timers, false);
                    }
                }
            }
        }
    }
}


float getProb(unsigned int node_id, unsigned int round, AttackGraph* ag, Prob* currents_prob){
    unsigned int nb_prob = ag->ag[node_id].nb_timed_preds;

    for(unsigned int i = 0; i < nb_prob; i++){
	
        if(ag->ag[node_id].timed_preds[i].r1 <= round && ag->ag[node_id].timed_preds[i].r2 >= round){
            currents_prob[node_id].r1 = ag->ag[node_id].timed_preds[i].r1;
            currents_prob[node_id].r2 = ag->ag[node_id].timed_preds[i].r2;
            currents_prob[node_id].prob = ag->ag[node_id].timed_preds[i].prob;
            return ag->ag[node_id].timed_preds[i].prob;
        }
    }

    return -1;
}


bool checkLeafProbAlreadyExists(unsigned int node_id, unsigned int round, AttackGraph* ag, Prob* currents_prob){

    if(currents_prob[node_id].r1 <= round && currents_prob[node_id].r2 >= round && currents_prob[node_id].prob != -1){
        return true;
    }
    return false;
}


bool testTimer(unsigned int id, unsigned int round, unsigned int step, TimerValue* timer, AttackGraph* ag){

    if(round < timer[id].start_round || round > timer[id].end_round){
        genTimer(id, round, timer, ag);
    }

    if(timer[id].timer >= step){
        timer[id].timer -= step;
    } else if(timer[id].timer < step){
        timer[id].timer = 0;
    }


    if(timer[id].timer == 0){
        genTimer(id, round, timer, ag);
        return true;
    }else{
        return false;
    }
}


void genTimer(unsigned int id, unsigned int round, TimerValue* timer, AttackGraph* ag){
    unsigned int nb_timers = ag->ag[id].nb_timers;
    bool flag = true;

	// Find the timer that match the curent round 
    for(unsigned int i = 0; i < nb_timers; i++){
        if(ag->ag[id].timers[i].r1 <= round && ag->ag[id].timers[i].r2 >= round){
        	// If it's always the previous timer that match the current round, use the second parameter
            if(timer->flag && timer->start_round == ag->ag[id].timers[i].r1 && timer->end_round == ag->ag[id].timers[i].r2){
                timer[id].timer = genRandom(ag->ag[id].timers[i].type2, ag->ag[id].timers[i].params2, ag->ag[id].timers[i].nb_params2, ag->getTimeUnit());
            }else{
                timer[id].timer = genRandom(ag->ag[id].timers[i].type1, ag->ag[id].timers[i].params1, ag->ag[id].timers[i].nb_params1, ag->getTimeUnit());
                timer[id].flag = true;
                timer[id].start_round = ag->ag[id].timers[i].r1;
                timer[id].end_round = ag->ag[id].timers[i].r2;

            }
            flag = false;
            break;
        }

        if(flag){
            timer[id].flag = false;
        }
    }
}


unsigned int genRandom(unsigned char type, float* params, unsigned int nb_params, string time_unit){
    std::random_device rng;
    std::default_random_engine generator(rng());
    if(type == NORMAL){
        std::normal_distribution<float> distribution(params[0], params[1]);
        return convertTimer(distribution(generator), time_unit);
    } else if(type == LOGNORMAL){
        std::lognormal_distribution<float> distribution(params[0], params[1]);
        return convertTimer(distribution(generator), time_unit);
    } else if (type == NONRANDOM){
        return params[0];
    } else {
        exit(1);
    }
}

unsigned int convertTimer(float timer, string time_unit){
    return round(timer);
}


unsigned int roundToTabIndex(unsigned int round, unsigned int step){
    return (unsigned int)(round / step);
}
