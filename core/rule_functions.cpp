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


#include "rule_functions.h"

bool sql_con_flag = false;
sql::Connection* con;

void defaultRuleFunction(void** params){

    AttackGraph* ag = (AttackGraph*) params[0];
    unsigned int node_id = ((unsigned int*) params[1])[0];
    json* config = (json*) params[2];

    float* params1 = (float*) calloc(1, sizeof(float));
    float* params2 = (float*) calloc(1, sizeof(float));
    params1[0] = 0;
    params2[0] = 0;

    ag->ag[node_id].timers = (Timer*) calloc(1, sizeof(Timer));

    string end_date_conf = config[0]["end"];
    string time_unit = config[0]["timeUnit"];
    ptime date(boost::posix_time::time_from_string(end_date_conf));
    unsigned long end_round = dateToRound(date, time_unit);

    ag->ag[node_id].timers[0] = Timer(0,end_round, NONRANDOM, params1, 1, NONRANDOM, params2, 1);
    ag->ag[node_id].nb_timers = 1;
}


void vulnExploitRuleFunction(void** params){

    static unordered_map<string, vector<Timer>> sql_cache;

    //Get back parameter values
    AttackGraph* ag = (AttackGraph*) params[0];
    unsigned int node_id = ((unsigned int*) params[1])[0];
    json* config = (json*) params[2];

    //Get back configuration about dates
    string end_date_conf = config[0]["end"];
    string time_unit = config[0]["timeUnit"];

    vector<Timer> temp_list_timer;
    float* params1 = (float*) calloc(2, sizeof(float));
    float* params2 = (float*) calloc(2, sizeof(float));

    unsigned int nb_dep = ag->ag[node_id].nb_dep;
    unsigned int parent_id;
    vector<string> splitted_line;
    vector<string> splitted_params;

    //Parse parent nodes to retrieve vulnExists and its associed CVE ID
    for(unsigned int i = 0; i < nb_dep; i++){
        parent_id = ag->ag[node_id].dependencies[i];
        boost::split(splitted_line, ag->ag[parent_id].description, [](char c){return c == '(';});

        if(splitted_line[0] == "vulExists"){
            boost::split(splitted_params, splitted_line[1], [](char c){return c == ',';});
            break;
        }
    }


    //Cache for vuln in database
    if(sql_cache.find(splitted_params[1]) != sql_cache.end()){
        temp_list_timer = sql_cache[splitted_params[1]];
    }else{
	
        //Connection to database and retrieve CVE exploits time to exploit
        string host = (*config)["database"]["host"];
        string user = (*config)["database"]["user"];
        string passwd = (*config)["database"]["passwd"];
        string dbname = (*config)["database"]["dbName"];

        try{
            bool flag_no_result = true;
            sql::Driver* driver;
            sql::Statement* stmt;
            sql::ResultSet* res;

            if(!sql_con_flag){
                sql_con_flag = true;
                driver = get_driver_instance();
                con = driver->connect(host, user, passwd);
            }
            con->setSchema(dbname);
            stmt = con->createStatement();
            res = stmt->executeQuery("SELECT * FROM `cve_prob_by_time` where cve_id=" + splitted_params[1] + ";");

            while (res->next()) {
                flag_no_result = false;
                ptime start_date(boost::posix_time::time_from_string(res->getString("from")));
                ptime end_date(boost::posix_time::time_from_string(res->getString("to")));

                params1[0] = stof(res->getString("attack_time_mu"));
                params1[1] = stof(res->getString("attack_time_sigma"));
                params2[0] = stof(res->getString("waiting_time_mu"));
                params2[1] = stof(res->getString("waiting_time_sigma"));
                temp_list_timer.push_back(Timer(dateToRound(start_date, time_unit),dateToRound(end_date, time_unit), LOGNORMAL, params1, 2, LOGNORMAL, params2, 2));
            }

            if(flag_no_result){
                cout << splitted_params[1] << " not found in database!" << endl;
                exit(1);
            }

            sql_cache[splitted_params[1]] = temp_list_timer;

            delete res;
            delete stmt;

        }catch(sql::SQLException &e){
            cout << "# ERR: " << e.what();
            cout << " (MySQL code error: " << e.getErrorCode();
            cout << ", SQL State: " << e.getSQLState() << " )" << endl;
        }
    }


    Timer* timers = (Timer*) calloc(temp_list_timer.size(), sizeof(Timer));

    for(unsigned int i = 0; i < temp_list_timer.size(); i++) {
        timers[i] = temp_list_timer[i];
    }
    ag->ag[node_id].timers = timers;
    ag->ag[node_id].nb_timers = temp_list_timer.size();
}


unsigned long dateToRound(ptime date, string time_unit){
    ptime start_date(boost::posix_time::time_from_string("1970-01-01 00:00:00"));
    time_duration duration = date - start_date;

    return duration.total_seconds();
}


unsigned long datesToRoundDuration(ptime start_date, ptime end_date, string time_unit){
    time_duration duration = end_date - start_date;

    return duration.total_seconds();
}
