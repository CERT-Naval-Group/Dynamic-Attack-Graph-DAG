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


import matplotlib.pyplot as plt
import numpy as np
import sys
import json
import os
import glob


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

def parseRes(file_path):
    final_res = []
    input_file = open(file_path, "r")
    res = input_file.read()
    input_file.close()
    parsed_res_by_line = res.split('\n')[:-1]
    for i in range(0,len(parsed_res_by_line)):
        final_res += [[float(elem) for elem in parsed_res_by_line[i].split(',')]]
    
    inverted_final_res = []
    for i in range(0, len(final_res[0])):
        inverted_final_res += [[]]

    for i in range(0, len(final_res)):
        for j in range(0, len(final_res[0])):
            inverted_final_res[j] += [final_res[i][j]]
            #final_res[i][j] = float(final_res[i][j])

    return final_res,inverted_final_res


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


def plotProbByTime(res, nodes_list, config_file, output_dir):
    # Remove old png files
    fileList = glob.glob(output_dir + "*.png")

    for filePath in fileList:
        try:
            os.remove(filePath)
        except:
            print("Error while deleting file : ", filePath)

    for i in range(0, len(res)):
        if(not whiteList(nodes_list[i + 1])):
            continue
        f = open(output_dir + nodes_list[i + 1] + "_" + str(i) + "_node.txt", "w+")
        f.write(str(res[i]))
        f.close()

        plt.clf()
        plt.plot(res[i])
        plt.xlabel(config_file["timeUnit"])
        plt.ylabel("Probability of " + nodes_list[i + 1])
        plt.savefig(output_dir + nodes_list[i + 1] + "_" + str(i) + "_node.png")


if __name__ == "__main__" :
    print("Uploading graphs...")
    config_file = parseConfig(sys.argv[1])
    working_dir = config_file["working_dir"]
    matrix, inverted_matrix = parseRes(working_dir + "sim_res/" + sys.argv[2])
    nodes_list = parseVertices(working_dir + "VERTICES.CSV")
    plotProbByTime(inverted_matrix, nodes_list, config_file, working_dir + "graphs/")
