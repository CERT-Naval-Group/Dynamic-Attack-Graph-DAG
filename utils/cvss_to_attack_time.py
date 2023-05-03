#  -------- copyright holders --------

#  This file is part of Dynamic Attack Graph GEneRator - DAGGER.

#  Dynamic Attack Graph GEneRator - DAGGER is free software; you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.

#  Dynamic Attack Graph GEneRator - DAGGER is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Lesser General Public License for more details.

#  You should have received a copy of the GNU Lesser General Public License
#  along with Dynamic Attack Graph GEneRator - DAGGER; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA


import mysql.connector
import datetime
import math



def CalcParam(mean, var):
	sigp = math.log(var / (math.exp(2 * math.log(mean))) + 1)
	
	mu = (math.log(var / (math.exp(sigp) - 1)) - sigp) / 2
	
	sig = math.sqrt(sigp)
	
	return mu,sig



query = []
val = []

db = mysql.connector.connect(host="localhost", user="phpmyadm",
                                 password="QRBIhj_ojXoUuzTS65vH", database="rpc")
cursor = db.cursor()
cursor.execute("TRUNCATE TABLE cve_prob_by_time;")

cursor.execute("SELECT publish_date, access_complexity, authentication, attack_complexity, privileges_required, user_interaction, id FROM cve;")

cve_list = cursor.fetchall()
for cve in cve_list:
    start_date = cve[0]
    end_date = datetime.datetime(2100, 1, 1, 0, 0, 0)


    if(cve[1] != None):
        if(cve[1] == "low"):
            access_complexity = 0.71
        elif(cve[1] == "medium"):
            access_complexity = 0.61
        elif (cve[1] == "high"):
            access_complexity = 0.35
        else:
            print("Value not excepted in access_complexity")
            exit(1)

    if (cve[2] != None):
        if (cve[2] == "none"):
            authentication = 0.704
        elif (cve[2] == "single"):
            authentication = 0.56
        elif (cve[2] == "multiple"):
            authentication = 0.45
        else:
            print("Value not excepted in authentication")
            exit(1)

    if (cve[3] != None):
        if (cve[3] == "low"):
            attack_complexity = 0.77
        elif (cve[3] == "high"):
            attack_complexity = 0.44
        else:
            print("Value not excepted in attack_complexity")
            exit(1)

    if (cve[4] != None):
        if (cve[4] == "none"):
            privileges_required = 0.88
        elif (cve[4] == "low"):
            privileges_required = 0.62
        elif (cve[4] == "high"):
            privileges_required = 0.27
        else:
            print("Value not excepted in privileges_required")
            exit(1)

    if (cve[5] != None):
        if (cve[5] == "none"):
            user_interaction = 0.85
        elif (cve[5] == "required"):
            user_interaction = 0.62
        else:
            print("Value not excepted in user_interaction")
            exit(1)




    if(cve[3] != None):
        x = attack_complexity * privileges_required * user_interaction
        exploit_score = -2.07181 * x + 1.15260
        if(exploit_score < 0):
            exploit_score = 0
        #print("CVSS3")
        #print("exploit_score = " + str(exploit_score))
    elif(cve[1] != None):
        x = access_complexity * authentication
        exploit_score = -2.92107 * x + 1.46007
        if(exploit_score < 0):
            exploit_score = 0
        #print("CVSS2")
        #print("exploit_score = " + str(exploit_score))

    else:
        continue

    time_to_exploit = exploit_score * 2678400 + 3600
    #print("time_to_exploit = " + str(time_to_exploit))
    
    mu, sigma = CalcParam(time_to_exploit, (50 * time_to_exploit / 100) ** 2)
    
    #sigma = 0.5
    #mu = math.log(time_to_exploit) - sigma * sigma / 2
    #print("mu = " + str(mu))
    time_to_exploit_learning = 60 * time_to_exploit / 100
    #mu_learning = math.log(time_to_exploit_learning) - sigma * sigma / 2
    
    mu_learning, sigma_learning = CalcParam(time_to_exploit_learning, (50 * time_to_exploit / 100) ** 2)

    val.append(cve[6])
    val.append(start_date)
    val.append(end_date)
    val.append(mu)
    val.append(sigma)
    val.append(mu_learning)
    val.append(sigma_learning)
    query.append("(%s, %s, %s, %s, %s, %s, %s),")

str_query = ''.join(query)
str_query = str_query[:-1]
val = tuple(val)
sql = "INSERT INTO `cve_prob_by_time` (`cve_id`, `from`, `to`, `attack_time_mu`, `attack_time_sigma`, `waiting_time_mu`, `waiting_time_sigma`) VALUES " + str_query + ";"
try:
    cursor.execute(sql, val)
    db.commit()
except mysql.connector.Error as err:
    print(sql)
    print(val)
    print(err)
    exit(1)
