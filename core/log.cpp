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


#include "log.h"


fstream log_file;
std::mutex file_lock;


void openLogFile(string path){
	log_file.open(path, fstream::app);
	log_file << "\n\nNew execution of DAG SIM\n\n\n";
}


void closeLogFile(){
	log_file.close();
}


void writeLog(string msg){
	auto current_clock = std::chrono::system_clock::now();
    std::time_t current_time = std::chrono::system_clock::to_time_t(current_clock);
    string current_date = std::ctime(&current_time);
    current_date.pop_back();
    
    file_lock.lock();
	log_file << current_date << ", " << msg << endl;
	file_lock.unlock();
}
