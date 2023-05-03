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
import sys


nb_vuln = int(sys.argv[1])

mydb = mysql.connector.connect(
    host="localhost",
    user="phpmyadm",
    passwd="QRBIhj_ojXoUuzTS65vH",
    database="rpc"
)

mycursor = mydb.cursor()


for i in range(0, nb_vuln):
    #sql = "INSERT INTO `cve` (`id`, `publish_date`, `last_update`, `description`, `base_score_v3`, `temporal_score_v3`, `exploitability_score_v3`, `impact_score_v3`, `base_score_v2`, `temporal_score_v2`, `exploitability_score_v2`, `impact_score_v2`, `attack_vector`, `attack_complexity`, `privileges_required`, `user_interaction`, `scope`, `access_vector`, `access_complexity`, `authentication`, `confidentiality_impact_v3`, `integrity_impact_v3`, `availability_impact_v3`, `confidentiality_impact_v2`, `integrity_impact_v2`, `availability_impact_v2`, `exploit_code_maturity`, `remediation_level_v3`, `report_confidence_v3`, `exploitability`, `remediation_level_v2`, `report_confidence_v2`, `gained_access`, `vector`, `cwe_id`) VALUES ('v" + str(i) + "', '2019-06-01', '2019-06-01', 'FAKE VULN', '10', NULL, '3.9', '6', '7.5', NULL, '10', '6.4', 'network', 'low', 'none', 'none', 'changed', 'network', 'low', 'none', 'high', 'high', 'high', 'partial', 'partial', 'partial', NULL, NULL, NULL, NULL, NULL, NULL, 'none', 'AV:N/AC:L/Au:N/C:P/I:P/A:P', 'CWE-119');"
    #mycursor.execute(sql)
    #mydb.commit()

    sql = "INSERT INTO `cve_prob_by_time` (`cve_id`, `from`, `to`, `attack_time_mu`, `attack_time_sigma`, `waiting_time_mu`, `waiting_time_sigma`) VALUES ('v" + str(i) + "', '2019-05-01 14:45:25', '2023-04-01 14:45:25', '8.0636', '0.5', '7.5528', '0.5');"
    mycursor.execute(sql)
    mydb.commit()
