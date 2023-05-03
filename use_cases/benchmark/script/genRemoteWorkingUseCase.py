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


import sys


nb_host = int(sys.argv[1])
nb_vuln = int(sys.argv[2])


output_file = open("../timed_input/main.P", "w")

output_file.write("attackerLocated(homeNetwork).[(2021-01-04 00:00:00,2021-01-24 23:59:59,1)]\n")
output_file.write("attackGoal(execCode(webServer,_)).\n")


for i in range(0, nb_vuln):
    output_file.write("vulExists(webServer, 'v" + str(i) + "', httpd, remoteExploit, privEscalation).[(2021-01-04 00:00:00,2021-01-24 23:59:59,1)]\n")


output_file.write("networkServiceInfo(webServer, serviceLAN, httpd, tcp , 80 , apache).[(2021-01-04 00:00:00,2021-01-24 23:59:59,1)]\n")
output_file.write("vlanInterface(webServer, serviceLAN).[(2021-01-04 00:00:00,2021-01-24 23:59:59,1)]\n\n")


for i in range(0, nb_host):
    output_file.write("attackGoal(execCode(h" + str(i) + ",_)).\n")
    output_file.write("firewallRule(h" + str(i) + ", userLAN, webServer, serviceLAN, tcp, 80).[(2021-01-04 00:00:00,2021-01-24 23:59:59,1)]\n")
    output_file.write("vulExists(h" + str(i) + ", 'CVE-2020-0796', smb, remoteExploit, privEscalation).[(2021-01-04 00:00:00,2021-01-24 23:59:59,1)]\n")
    output_file.write("networkServiceInfo(h" + str(i) + ", _, smb, tcp, 445, root).[(2021-01-04 00:00:00,2021-01-24 23:59:59,1)]\n")
    if(i % 3 == 0):
        output_file.write("vlanInterface(h" + str(i) + ", homeNetwork).[(2021-01-04 00:00:00,2021-01-10 23:59:59,1)]\n")
        output_file.write("vlanInterface(h" + str(i) + ", userLAN).[(2021-01-11 00:00:00,2021-01-24 23:59:59,1)]\n")
    elif(i % 3 == 1):
        output_file.write("vlanInterface(h" + str(i) + ", homeNetwork).[(2021-01-11 00:00:00,2021-01-17 23:59:59,1)]\n")
        output_file.write("vlanInterface(h" + str(i) + ", userLAN).[(2021-01-04 00:00:00,2021-01-10 23:59:59,1), (2021-01-18 00:00:00,2021-01-24 23:59:59,1)]\n")
    elif(i % 3 == 2):
        output_file.write("vlanInterface(h" + str(i) + ", homeNetwork).[(2021-01-18 00:00:00,2021-01-24 23:59:59,1)]\n")
        output_file.write("vlanInterface(h" + str(i) + ", userLAN).[(2021-01-04 00:00:00,2021-01-17 23:59:59,1)]\n")
    else:
        print("WTF!")
        exit(42)

    output_file.write("\n")





output_file.close()
