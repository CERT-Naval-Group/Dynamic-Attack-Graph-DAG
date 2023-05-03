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


#include "attack_graph.h"

AttackGraph::AttackGraph(){
    this->nb_fact_nodes = 0;
    this->nb_rule_nodes = 0;
}


/*
Graph looks like ["description", [dependencies], [children], nb_dependencies, nb_children, node_type, [timers], nb_timers, [timed_predicats], nb_timed_predicats] for each node
*/
void AttackGraph::buildGraph(){
    cout << "Loading attack graph!" << endl;
    auto start = std::chrono::high_resolution_clock::now();
    
    //Allocating memory for attack graph
    this->ag = (Node*) calloc(this->graph_size + 1, sizeof(Node));

    string buffer;
    unsigned int node_id;
    vector<string> splitted_line;
    vector<string> splitted_literal;
    ifstream vertices_file(this->vertices_file_path);
    ifstream arcs_file(this->arcs_file_path);



    //Parsing VERTICES.CSV file
    while (getline (vertices_file, buffer)) {
        boost::split(splitted_line, buffer, [](char c){return c == '"';});
        boost::split(splitted_literal, splitted_line[1], [](char c){return c == '(';});

        node_id = stoi(splitted_line[0]);

        this->ag[node_id].description = splitted_line[1];

        if(splitted_line[3] == "AND"){
            this->ag[node_id].type = RULE;
            this->nb_rule_nodes ++;
        }
        else if(splitted_line[3] == "LEAF"){
            this->ag[node_id].type = LEAF;
            this->nb_fact_nodes ++;
        }
        else if(find(config["stateNodes"].begin(), config["stateNodes"].end(), splitted_literal[0]) != config["stateNodes"].end()){
            this->ag[node_id].type = STATE;
            this->nb_fact_nodes ++;
        }
        else{
            this->ag[node_id].type = CONDITION;
            this->nb_fact_nodes ++;
        }
    }
    vertices_file.close();



    //Allocating memory for arcs between nodes
    vector<unsigned int>* temp_parent_nodes = (vector<unsigned int>*)calloc(this->graph_size + 1, sizeof(vector<unsigned int>));

    vector<unsigned int>* temp_child_nodes = (vector<unsigned int>*)calloc(this->graph_size + 1, sizeof(vector<unsigned int>));
    for(unsigned int i = 1; i < this->graph_size + 1; i++){
        temp_parent_nodes[i] = vector<unsigned int>();
        temp_child_nodes[i] = vector<unsigned int>();
    }

    unsigned int child_node, parent_node;

    //Parsing ARCS.CSV file
    while (getline (arcs_file, buffer)) {
        boost::split(splitted_line, buffer, [](char c){return c == ',';});
        child_node = stoi(splitted_line[0]);
        parent_node = stoi(splitted_line[1]);

        temp_parent_nodes[child_node].push_back(parent_node);
        temp_child_nodes[parent_node].push_back(child_node);
    }


    unsigned int k = 0;  //For fact_nodes list
    unsigned int l = 0;  //For rule_nodes list
    this->rule_nodes = (unsigned int*) calloc(this->nb_rule_nodes, sizeof(unsigned int));
    this->fact_nodes = (unsigned int*) calloc(this->nb_fact_nodes, sizeof(unsigned int));
    for(unsigned int i = 1; i < this->graph_size + 1; i++){
        this->ag[i].dependencies = (unsigned int*) calloc(temp_parent_nodes[i].size(), sizeof(unsigned int));

        for(unsigned int j = 0; j < temp_parent_nodes[i].size(); j++){
            this->ag[i].dependencies[j] = temp_parent_nodes[i][j];
        }
        this->ag[i].nb_dep = temp_parent_nodes[i].size();

        this->ag[i].children = (unsigned int*) calloc(temp_child_nodes[i].size(), sizeof(unsigned int));

        for(unsigned int j = 0; j < temp_child_nodes[i].size(); j++){
            this->ag[i].children[j] = temp_child_nodes[i][j];
        }
        this->ag[i].nb_child = temp_child_nodes[i].size();

        if(this->ag[i].type == RULE){
            this->rule_nodes[l] = i;
            l++;
        }else{
            this->fact_nodes[k] = i;
            k++;
        }
    }


    //Free memory
    for(unsigned int i = 1; i < this->graph_size + 1; i++){
        temp_parent_nodes[i] = vector<unsigned int>();
        temp_child_nodes[i] = vector<unsigned int>();
    }
    free(temp_parent_nodes);
    free(temp_child_nodes);


    cout << "Creation of timers and timed predicats" << endl;


    //Parse timed_input.P file
    //map<string, map<string, Pred>> timed_predicat;
    //this->timedInputParser(timed_predicat);
    
    map<string, Literal> timed_predicat;
    this->timedInputParser(timed_predicat);

	//cout << timed_predicat["vlanInterface"].params_list["webServer"].params_list["serviceLAN"].pred.params[0] << endl;

	
    //Build timers and timed predicats
    for(unsigned int i = 1; i < this->graph_size + 1; i++){    
        if(this->ag[i].type == RULE){
            //Build timers
            this->buildTimers(i);
        } else {
            //Build timed predicat
            this->buildTimedPredicats(i, timed_predicat);
        }
    }


    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    float duration_time = (float) duration.count() / 1000.0;

    cout << "Attack graph has been loaded in " << duration_time << " seconds" << endl;
}


void AttackGraph::buildTimedPredicats(unsigned int node_id, map<string, Literal> &timed_predicat){

    vector<string> splitted_line, splitted_params;
    boost::split(splitted_line, this->ag[node_id].description, [](char c){return c == '(';});

    string predicat = splitted_line[0];
    string params = splitted_line[1].substr(0, splitted_line[1].size()-1);
     
    boost::split(splitted_params, params, [](char c){return c == ',';});


    if(timed_predicat.find(predicat) != timed_predicat.end()){
    	if(timed_predicat[predicat].pred_list.find(params) != timed_predicat[predicat].pred_list.end()){
    	
    		//cout << "MATCH!" << endl;
    		this->ag[node_id].nb_timed_preds = timed_predicat[predicat].pred_list[params].nb_probs;
		    this->ag[node_id].timed_preds = (Prob*) calloc(timed_predicat[predicat].pred_list[params].nb_probs, sizeof(Prob));
		    
		    for(unsigned int i = 0; i < timed_predicat[predicat].pred_list[params].nb_probs; i++){
                Prob prob;
                prob.r1 = timed_predicat[predicat].pred_list[params].timed_probs[i].r1;
                prob.r2 = timed_predicat[predicat].pred_list[params].timed_probs[i].r2;
                prob.prob = timed_predicat[predicat].pred_list[params].timed_probs[i].prob;
                this->ag[node_id].timed_preds[i] = prob;
            }
    	}else{
    		//cout << "MISSED!    " << params << endl;
    		
    		Param* param_buff;
    		if(timed_predicat[predicat].params_list.find(splitted_params[0]) != timed_predicat[predicat].params_list.end()){
    			param_buff = &timed_predicat[predicat].params_list[splitted_params[0]];
    		} else if(timed_predicat[predicat].params_list.find("_") != timed_predicat[predicat].params_list.end()){
    			param_buff = &timed_predicat[predicat].params_list["_"];
    		} else {
    			//cout << "Param " << splitted_params[0] << " not found for predicat " << predicat << endl;
    			return;
    			//exit(1);
    		}
    		
    		for(unsigned int i = 1; i < splitted_params.size(); i++){
    			if(param_buff->params_list.find(splitted_params[i]) != param_buff->params_list.end()){
    				param_buff = &param_buff->params_list[splitted_params[i]];
    			} else if(param_buff->params_list.find("_") != param_buff->params_list.end()){
					param_buff = &param_buff->params_list["_"];
				} else {
					//cout << "Param " << splitted_params[i] << " not found for predicat " << predicat << endl;
					return;
					//exit(1);
				}
    		}
    		
    		this->ag[node_id].nb_timed_preds = param_buff->pred.nb_probs;
		    this->ag[node_id].timed_preds = (Prob*) calloc(param_buff->pred.nb_probs, sizeof(Prob));
		    
		    for(unsigned int i = 0; i < param_buff->pred.nb_probs; i++){
                Prob prob;
                prob.r1 = param_buff->pred.timed_probs[i].r1;
                prob.r2 = param_buff->pred.timed_probs[i].r2;
                prob.prob = param_buff->pred.timed_probs[i].prob;
                this->ag[node_id].timed_preds[i] = prob;
            }
    		
    		
		    /*for(map<string, Pred>::iterator it = timed_predicat[predicat].begin(); it != timed_predicat[predicat].end(); ++it){
		        if(this->matchPred(params, it->second.params, it->second.nb_params)){

					cout << "   " << it->first << endl;

		            this->ag[node_id].nb_timed_preds = it->second.nb_probs;
		            this->ag[node_id].timed_preds = (Prob*) calloc(it->second.nb_probs, sizeof(Prob));

		            for(unsigned int i = 0; i < it->second.nb_probs; i++){
		                Prob prob;
		                prob.r1 = it->second.timed_probs[i].r1;
		                prob.r2 = it->second.timed_probs[i].r2;
		                prob.prob = it->second.timed_probs[i].prob;
		                this->ag[node_id].timed_preds[i] = prob;
		            }
		            break;
		        }
		    }*/
		}
    }
}


bool AttackGraph::matchPred(string params1, string* params2, unsigned int nb_params2){
    vector<string> splitted_params1;
    boost::split(splitted_params1, params1, [](char c){return c == ',';});

    if(splitted_params1.size() != nb_params2){
        return false;
    }

    for(unsigned int i = 0; i < nb_params2; i++){
        if(params2[i] != splitted_params1[i] && params2[i] != "_"){
            return false;
        }
    }

    return true;
}


void AttackGraph::buildTimers(unsigned int node_id){
    vector<string> splitted_line;
    string rule_name;
    void** params = (void**) calloc(3, sizeof(void*));
    params[0] = this;
    params[1] = &node_id;
    params[2] = &(this->config);

    boost::split(splitted_line, this->ag[node_id].description, [](char c){return c == '(';});

    rule_name = splitted_line[1].substr(0, splitted_line[1].size()-1);
    
    if(this->timer_functions.find(rule_name) == this->timer_functions.end()){
        this->timer_functions["default"](params);
    } else {
        this->timer_functions[rule_name](params);
    }
}


void AttackGraph::setConfigFile(json config){
    this->config = config;

    this->vertices_file_path = (string)(this->config["working_dir"]) + "VERTICES.CSV";
    this->arcs_file_path = (string)(this->config["working_dir"]) + "ARCS.CSV";
}


void AttackGraph::setGraphSize(){
    unsigned int cpt = 0;
    string buffer;
    ifstream file(this->vertices_file_path);

    while (getline (file, buffer)) {
        cpt++;
    }
    this->graph_size = cpt;
    file.close();
}


unsigned int AttackGraph::getGraphSize(){
    return this->graph_size;
}


string AttackGraph::getTimeUnit(){
    return this->config["timeUnit"];
}


unsigned int AttackGraph::getNbRuleNodes(){
    return this->nb_rule_nodes;
}


unsigned int AttackGraph::getNbFactNodes(){
    return this->nb_fact_nodes;
}


unsigned int* AttackGraph::getRuleNodes(){
    return this->rule_nodes;
}


unsigned int* AttackGraph::getFactNodes(){
    return this->fact_nodes;
}


ostream& operator<<(ostream& os, const AttackGraph& self){
    for (unsigned int i = 1; i < self.graph_size + 1; i++){
        os << self.ag[i].description << ", ";


        os << "[";
        for(unsigned int j = 0; j < self.ag[i].nb_dep; j++){
            os << self.ag[i].dependencies[j] << ",";
        }
        os << "], ";


        os << "[";
        for(unsigned int j = 0; j < self.ag[i].nb_child; j++){
            os << self.ag[i].children[j] << ",";
        }
        os << "], ";

        os << self.ag[i].nb_dep << ", ";

        os << self.ag[i].nb_child << ", ";


        if(self.ag[i].type == RULE){
            os << "RULE" << ", ";
        }
        else if(self.ag[i].type == LEAF){
            os << "LEAF" << ", ";
        }
        else if(self.ag[i].type == STATE){
            os << "STATE" << ", ";
        }
        else if(self.ag[i].type == CONDITION){
            os << "CONDITION" << ", ";
        }


        //Print timers
        os << "[";

        for(unsigned int j = 0; j < self.ag[i].nb_timers; j++){
            os << "[";

            os << self.ag[i].timers[j].r1 << ", ";
            os << self.ag[i].timers[j].r2 << ", ";

            if(self.ag[i].timers[j].type1 == NONRANDOM){
                os << "NONRANDOM" << ", ";
            }
            else if(self.ag[i].timers[j].type1 == NORMAL){
                os << "NORMAL" << ", ";
            }
            else if(self.ag[i].timers[j].type1 == LOGNORMAL){
                os << "LOGNORMAL" << ", ";
            }
            else if(self.ag[i].timers[j].type1 == UNIFORM){
                os << "UNIFORM" << ", ";
            }
            else if(self.ag[i].timers[j].type1 == TRIANGULAR){
                os << "TRIANGULAR" << ", ";
            }

            os << "(";

            for(unsigned int k = 0; k < self.ag[i].timers[j].nb_params1; k++){
                os << self.ag[i].timers[j].params1[k] << ", ";
            }

            os << "), ";

            if(self.ag[i].timers[j].type2 == NONRANDOM){
                os << "NONRANDOM" << ", ";
            }
            else if(self.ag[i].timers[j].type2 == NORMAL){
                os << "NORMAL" << ", ";
            }
            else if(self.ag[i].timers[j].type2 == LOGNORMAL){
                os << "LOGNORMAL" << ", ";
            }
            else if(self.ag[i].timers[j].type2 == UNIFORM){
                os << "UNIFORM" << ", ";
            }
            else if(self.ag[i].timers[j].type2 == TRIANGULAR){
                os << "TRIANGULAR" << ", ";
            }

            os << "(";

            for(unsigned int k = 0; k < self.ag[i].timers[j].nb_params2; k++){
                os << self.ag[i].timers[j].params2[k] << ", ";
            }

            os << ")";

            os << "]";
        }

        os << "], ";

        os << self.ag[i].nb_timers << ", ";


        //Print timed inputs
        cout << "[";
        for(unsigned int j = 0; j < self.ag[i].nb_timed_preds; j++){
            cout << "(" << self.ag[i].timed_preds[j].r1 << ", " << self.ag[i].timed_preds[j].r2 << ", " << self.ag[i].timed_preds[j].prob << "), ";
        }
        cout << "], ";

        cout << self.ag[i].nb_timed_preds;

        os << endl;
    }
    return os;
}


void AttackGraph::setRuleFunction(string rule_name, void (*setTimer)(void** params)){
    this->timer_functions[rule_name] = setTimer;
}


Timer::Timer(unsigned long r1, unsigned long r2, unsigned char type1, float* params1, unsigned int nb_params1, unsigned char type2, float* params2, unsigned int nb_params2){
    this->r1 = r1;
    this->r2 = r2;
    this->type1 = type1;
    this->params1 = params1;
    this->nb_params1 = nb_params1;
    this->type2 = type2;
    this->params2 = params2;
    this->nb_params2 = nb_params2;
}


void AttackGraph::timedInputParser(map<string, Literal> &timed_predicat){

    string time_unit = this->config["timeUnit"];
    vector<string> splitted_line, splitted_predicat, splitted_params, splitted_times;
    string predicat, params;
    string buffer;
    ifstream file((string)this->config["working_dir"] + "timed_input.P");


    while (getline (file, buffer)) {
        if(buffer == ""){
            continue;
        }

        boost::split(splitted_line, buffer, [](char c){return c == '[';});
        boost::erase_all(splitted_line[0], " ");

        boost::split(splitted_predicat, splitted_line[0], [](char c){return c == '(';});
        predicat = splitted_predicat[0];

        if(predicat == "attackGoal"){
            continue;
        }
        params = splitted_predicat[1].substr(0, splitted_predicat[1].size()-2);
        boost::split(splitted_params, params, [](char c){return c == ',';});

        //TODO Replace all these erase by a single one
        boost::erase_all(splitted_line[1], "[");
        boost::erase_all(splitted_line[1], "]");
        boost::erase_all(splitted_line[1], "(");
        boost::erase_all(splitted_line[1], ")");
        boost::replace_all(splitted_line[1], ", ", ",");

        boost::split(splitted_times, splitted_line[1], [](char c){return c == ',';});


        //map<string, Pred> predicat_map;
        Pred pred;
        Prob prob;
        pred.nb_params = splitted_params.size();
        pred.params = (string*) calloc(splitted_params.size(), sizeof(string));
        for(unsigned int i = 0; i < splitted_params.size(); i++){
            pred.params[i] = splitted_params[i];
        }


        pred.nb_probs = splitted_times.size() / 3;
        pred.timed_probs = (Prob*) calloc(pred.nb_probs, sizeof(Prob));
        for(unsigned int i = 0, j = 0; i < splitted_times.size(); i += 3, j++){
            ptime start_date(boost::posix_time::time_from_string(splitted_times[i]));
            ptime end_date(boost::posix_time::time_from_string(splitted_times[i+1]));


            prob.r1 = dateToRound(start_date, time_unit);
            prob.r2 = dateToRound(end_date, time_unit);
            prob.prob = stof(splitted_times[i+2]);

            pred.timed_probs[j] = prob;
        }

		/*
        if(timed_predicat.find(predicat) == timed_predicat.end()){
            //predicat_map[params] = pred;
            //timed_predicat[predicat] = predicat_map;
        }
        else {
            //timed_predicat[predicat][params] = pred;
        }*/
        
        if(timed_predicat.find(predicat) == timed_predicat.end()){
        	Literal lit;
        	
        	map<string, Pred> pred_list;
        	pred_list[params] = pred;
        	
        	Param p;
        	map<string, Param> p_list;
        	p.params_list = p_list;
        	map<string, Param> params_list;
        	params_list[splitted_params[0]] = p;
        	
        	lit.pred_list = pred_list;
        	lit.params_list = params_list;
        	
        	timed_predicat[predicat] = lit;
        }else{
        	timed_predicat[predicat].pred_list[params] = pred;
        	
        	if(timed_predicat[predicat].params_list.find(splitted_params[0]) == timed_predicat[predicat].params_list.end()){
        		Param p;
        		map<string, Param> p_list;
        		p.params_list = p_list;
        		timed_predicat[predicat].params_list[splitted_params[0]] = p;
        	}
        }
        
        unsigned int k;
        Param* param_buff = &timed_predicat[predicat].params_list[splitted_params[0]];
        
        //cout << predicat << " : " << splitted_params[0] << ", ";
        
        for(k = 1; k < splitted_params.size(); k++){
        	//cout << splitted_params[k] << ", ";
        
        	if(param_buff->params_list.find(splitted_params[k]) == param_buff->params_list.end()){
        		Param new_param;
        		map<string, Param> params_list;
        		new_param.params_list = params_list;
        		param_buff->params_list[splitted_params[k]] = new_param;
        	}
        	param_buff = &param_buff->params_list[splitted_params[k]];
        }
        param_buff->pred = pred;
        //cout << endl;


        //cout << buffer << endl;
        //cout << predicat << endl;
        //cout << params << endl;
        //cout << splitted_params[0] << endl;
        //cout << splitted_line[1] << endl;
    }

    /*
    cout << timed_predicat.size() << endl;
    for(map<string,map<string, Pred>>::iterator it = timed_predicat.begin(); it != timed_predicat.end(); ++it) {
        cout << it->first << ": [";

        for(map<string, Pred>::iterator sit = it->second.begin(); sit != it->second.end(); ++sit) {
            cout << "\"" << sit->first << "\": [";

            cout << "[";
            for(int i = 0; i < sit->second.nb_params; i++){
                cout << sit->second.params[i] << ", ";
            }
            cout << "], [";

            for(int i = 0; i < sit->second.nb_probs; i++){
                cout << "(";
                cout << sit->second.timed_probs[i].r1 << ", ";
                cout << sit->second.timed_probs[i].r2 << ", ";
                cout << sit->second.timed_probs[i].prob;
                cout << "), ";
            }
            cout << "]";

            cout << "]";
        }

        cout << "]" << endl;
    }
    */

    //return timed_predicat;
}
