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

#ifndef RULE_FUNCTIONS_H
#define RULE_FUNCTIONS_H


#include <iostream>
#include <stdlib.h>
#include <math.h>

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <unordered_map>

#include "json.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"

#include "attack_graph.h"

#define NONRANDOM 0
#define NORMAL 1
#define LOGNORMAL 2
#define UNIFORM 3
#define TRIANGULAR 4

using namespace std;
using ptime = boost::posix_time::ptime;
using time_duration = boost::posix_time::time_duration;


unsigned long dateToRound(ptime date, string time_unit);

unsigned long datesToRoundDuration(ptime start_date, ptime end_date, string time_unit);

unsigned long durationToRound(time_duration duration, string time_unit);

unsigned long durationToRound(unsigned long duration, string time_unit);

void defaultRuleFunction(void** params);

void vulnExploitRuleFunction(void** params);


#endif
