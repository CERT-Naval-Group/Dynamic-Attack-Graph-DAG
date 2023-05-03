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


import csv
import sys
import json
import sys


def parseConfig(file_path):
    input_file = open(file_path, "r")
    res = input_file.read()
    input_file.close()
    return json.loads(res)


def parseVertices(file_path):
    nodes_list = {}
    with open(file_path) as input_file:
        for line in input_file:
            splited_line = line.split('"')
            uid = int(splited_line[0][:-1])
            name = splited_line[1]
            nodes_list[uid] = name
    return nodes_list


def whiteList(node):
    if(node[0] == 'e' and node[1] == 'x' and node[2] == 'e' and node[3] == 'c'):
        return True
    if(node[0] == 'a' and node[1] == 'v' and node[2] == 'a'):
        return True
    if(node[0] == 'd' and node[1] == 'd' and node[2] == 'o'):
        return True 
    if(node[0] == 'c' and node[1] == 'o' and node[2] == 'n'):
        return True
    return False


def getTimeToCompromise(file_path, prob, nodes_list):
    res = {}
    nb_nodes = len(nodes_list)

    for k in range(0, nb_nodes):
        res[k + 1] = -1
    
    with open(file_path, 'r') as csvfile:
        csvreader = csv.reader(csvfile) 
        i = 0
        for row in csvreader:           
            for j in range(0, len(row)):
                if(res[j + 1] == -1 and float(row[j]) > prob):
                    res[j + 1] = i

            i += 1

    with open('ttc.txt', 'w') as f:
        for node_id in res:
            f.write(str(node_id) + ", " + nodes_list[node_id] + " : " + str(res[node_id]) + "\n")                



if __name__ == "__main__" :
    config_file = parseConfig(sys.argv[1])
    working_dir = config_file["working_dir"]
    nodes_list = parseVertices(working_dir + "VERTICES.CSV")
    file_path = sys.argv[2]
    getTimeToCompromise(file_path, float(sys.argv[3]), nodes_list)
