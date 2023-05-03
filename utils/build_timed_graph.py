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


import re
import json
import sys
import os
from os import listdir
from os.path import isfile, join
import itertools
import datetime
import time as ti
import subprocess
import time



class RiskPropagationCalculator :

    def __init__(self, config_file_path):
        self.timed_predicats = {}
        self.config = {}
        self.config_file_path = config_file_path
        self.parseConfigFile()
        self.working_dir = self.config["working_dir"]
        self.initTimedInput()
        self.timed_input_path = self.working_dir + "timed_input.P"
        self.input_path = self.working_dir + "input.P"
        self.initInput()
        self.execMulval()
        
        if(self.config["optimization"] == True):
            start_time = time.time()
            self.optimizer()
            print("Execution time of the optimization : " + str(round(time.time() - start_time, 3)) + " seconds")




    def parseTimedInputLine(self, line):
        if(len(line.split('[')) == 2):
            dates = "[" + line.split('[')[1]
        else:
            dates = ""

        predicat = line.replace(" ", "").split('[')[0][:-1].split('(')[0]
        params = line.replace(" ", "").split('[')[0][:-1].split('(')[1].replace(')', '').split(',')

        return predicat, params, dates



    def initTimedInput(self):
        print("Parsing timed input files...")
        self.attacker_goals = {}
        lines_seen = set()
        with open(self.working_dir + "timed_input.P", 'w') as outfile:
            fileList = []
            with open(self.working_dir + self.config["timedInputDir"] + "main.P", 'r') as infile:
                line = infile.readline()
                while(line):
                    if(line[0] == '/' or line[0] == '\n'):
                        line = infile.readline()
                        continue
                    elif(line[0] == '#'):
                        if(line[-1] == '\n'):
                            line = line[:-1]
                        fileList.append(self.working_dir + self.config["timedInputDir"] + line.split('<')[1][:-1])
                        line = infile.readline()
                    else:
                        break

            fileList.append(self.working_dir + self.config["timedInputDir"] + "main.P")
            var_list = {}
            for filePath in fileList:
                with open(filePath, 'r') as infile:
                    outfile.write('\n')
                    line = infile.readline()
                    while(line):
                        reg_var = "^attackGoal"
                        b = re.search(reg_var, line)

                        if (line[0] == '\n'):
                            #outfile.write(line)
                            line = infile.readline()
                            continue
                        elif(line[0] == '/' or line[0] == "#"):
                            line = infile.readline()
                            continue
                        elif(b != None):
                            cp_line = line
                            if(cp_line[-1] != '\n'):
                                cp_line = cp_line + "\n"

                            line = line.replace("attackGoal(", "").replace("))", ")")
                            if (line[-1] == '\n'):
                                line = line[:-1]
                            line = line[:-1]
                            pred = line.split('(')[0]
                            params = line.split('(')[1][:-1].split(',')
                            if (pred not in self.attacker_goals):
                                self.attacker_goals[pred] = [params]
                            else:
                                self.attacker_goals[pred].append(params)
                            outfile.write(cp_line)
                        else:
                            #Check if it's var
                            reg_var = "^[A-Z]"
                            b = re.search(reg_var, line)
                            if (b != None):
                                if(line[-1] == '\n'):
                                    line = line[:-1]
                                splitted_var = line.replace(" ", "").split('=')
                                var_list[splitted_var[0]] = splitted_var[1].replace("[", "").replace("]", "").split(',')
                            else:
                                #Parse line
                                predicat, params, dates = self.parseTimedInputLine(line)

                                new_params = []
                                for param in params:
                                    if(re.search(reg_var, param) ==None):
                                        new_params += [[param]]
                                    else:
                                        new_params += [var_list[param]]

                                for final_param in itertools.product(*new_params):
                                    if(len(final_param) == 1):
                                        final_param = str(final_param).replace(',', '')
                                    output_line = (str(predicat) + str(final_param) + "." + str(dates)).replace('\'', '').replace('\"', '\'')
                                    if(output_line[-1] != '\n'):
                                        output_line = output_line + "\n"

                                    if(output_line[-1] == '\n'):
                                        line_to_compare = output_line[:-1]
                                    else:
                                        line_to_compare = output_line
                                    if(line_to_compare not in lines_seen):
                                        lines_seen.add(line_to_compare)
                                        outfile.write(output_line)
                        line = infile.readline()



    def initInput(self):
        with open(self.timed_input_path, 'r') as f:
            for i, l in enumerate(f):
                pass
        i = 0
        query = []
        val = []

        with open(self.timed_input_path, 'r') as infile:
            with open(self.input_path, 'w') as outfile:
                line = infile.readline()
                while(line):
                    i += 1
                    # Ignore comments
                    if(line[0] == '/'):
                        line = infile.readline()
                        continue

                    # Split predicat from time range
                    res_lines = line.split('[')
                    predicat = res_lines[0]
                    if (predicat[-1] == '\n'):
                        predicat = predicat[:-1]
                    outfile.write(predicat + "\n")
                    temp_id = predicat[:-1]
                    id = temp_id.replace(" ", "")
                    if(len(res_lines) == 2):
                        dates = res_lines[1]
                        if(dates[-1] == '\n'):
                            dates = dates[:-1]
                        if(dates[-1] == ']'):
                            dates = dates[:-1]
                        date_list = dates.split(')')
                        for date in date_list:
                            if(date == "\n" or date == ""):
                                continue
                            while(date[0] != '('):
                                date = date[1:]
                            date = date[1:]
                            start_date, end_date, prob = date.replace(", ", '').split(',')

                            pred = id.split('(')[0]
                            params = "(" + id.split('(')[1]
                            params_list = params[1:-1].split(',')
                            query.append("(%s, %s, %s, %s),")
                            val.append(id)
                            val.append(start_date)
                            val.append(end_date)
                            val.append(prob)

                            start_date_list = start_date.replace(' ', '-').replace(':', '-').split('-')
                            end_date_list = end_date.replace(' ', '-').replace(':', '-').split('-')
                            start_date = self.datetimeToRound(datetime.datetime(int(start_date_list[0]), int(start_date_list[1]), int(start_date_list[2]), int(start_date_list[3]), int(start_date_list[4]), int(start_date_list[5])))
                            end_date = self.datetimeToRound(datetime.datetime(int(end_date_list[0]), int(end_date_list[1]), int(end_date_list[2]), int(end_date_list[3]), int(end_date_list[4]), int(end_date_list[5])))
                            if (pred not in self.timed_predicats):
                                self.timed_predicats[pred] = {params: [params_list, [(start_date, end_date, float(prob))]]}
                            else:
                                if(params not in self.timed_predicats[pred]):
                                    self.timed_predicats[pred][params] = [params_list, [(start_date, end_date, float(prob))]]
                                else:
                                    self.timed_predicats[pred][params][1].append((start_date, end_date, float(prob)))
                    line = infile.readline()



    def execMulval(self):
        rules_file = ""
        if("rules_path" in self.config.keys()):
            rules_file = "-r " + self.config["rules_path"]
        bash_script="#!/bin/bash\n\nworkingdir='" + self.working_dir + "'\ncurrentdir=$(pwd)\n\ncd ${workingdir}\n$MULVALROOT/utils/graph_gen.sh -v input.P " + rules_file + "\ncd $currentdir"
        with open(self.working_dir + "mulval.sh", 'w') as outfile:
            outfile.write(bash_script)
        args = ("/bin/bash", self.working_dir + "mulval.sh", self.working_dir)
        print("Attack graph generation with MulVAL...")
        start_time = ti.time()
        popen = subprocess.Popen(args, stdout=subprocess.PIPE)
        popen.wait()
        output = popen.stdout.read()
        end_time = ti.time()
        print("------------ MulVAL output ------------")
        print(output.decode("utf-8").replace("\n\n", "\t").replace("\n", " ").replace("\t", "\n"))
        print("Execution time of MulVAL : " + str(round(end_time - start_time, 3)) + " seconds")
        print("---------------------------------------")
        os.remove(self.working_dir + "mulval.sh")
        #os.remove(self.working_dir + "ARCS.CSV")
        #os.remove(self.working_dir + "AttackGraph.txt")
        os.remove(self.working_dir + "AttackGraph.xml")
        os.remove(self.working_dir + "dynamic_decl.gen")
        os.remove(self.working_dir + "environment.P")
        os.remove(self.working_dir + "environment.xwam")
        #os.remove(self.working_dir + "input.P")
        os.remove(self.working_dir + "log_for_me.log")
        os.remove(self.working_dir + "metric.P")
        os.remove(self.working_dir + "run.P")
        os.remove(self.working_dir + "run.xwam")
        os.remove(self.working_dir + "running_rules.P")
        #os.remove(self.working_dir + "timed_input.P")
        os.remove(self.working_dir + "trace_output.P")
        os.remove(self.working_dir + "translated_rules.P")
        #os.remove(self.working_dir + "VERTICES.CSV")
        os.remove(self.working_dir + "xsb_log.txt")
        

    def optimizer(self):
        print("Optimization...")

        nodes = {}
        edges = {}
        allowed_literals = ["execCode", "availability", "confidentiality", "ddos"]
        disallowed_literals = ["netAccess", "lanAccess"]
        
        node_file = open(self.working_dir + "VERTICES.CSV")
        edge_file = open(self.working_dir + "ARCS.CSV")

        for line in node_file:
            splitted_line = line.split('"')
            nodes[splitted_line[0][:-1]] = splitted_line[1]

        for line in edge_file:
            splitted_line = line.split(',')
            if(splitted_line[0] not in edges):
                edges[splitted_line[0]] = [[], []]

            if(splitted_line[1] not in edges):
                edges[splitted_line[1]] = [[], []]

            edges[splitted_line[0]][1] += [splitted_line[1]]
            edges[splitted_line[1]][0] += [splitted_line[0]]


        nodes_to_analyse = list(nodes)
        flag = False

        while(True):
            nodes_buff = {}
            edges_buff = {}
            #nodes_to_analyse_buff = list(nodes_to_analyse)
            analyzed_nodes = []
            for node in nodes_to_analyse:
                node_desc = nodes[node]
                analyzed_nodes += [node]
                #nodes_to_analyse_buff.remove(node)
                
                if("RULE" not in node_desc):  # Literal node
                    if(len(edges[node][1]) > 0):      # Derived literals
                        if(node_desc.split('(')[0] not in allowed_literals):  # Not allowed literals
                            nb_parents = len(edges[node][1])
                            nb_child = len(edges[node][0])
                            if(nb_parents * nb_child < nb_parents + nb_child + 1):
                                parent_rule_nodes = edges[node][1]
                                child_rule_nodes = edges[node][0]
                                new_node_id = parent_rule_nodes + child_rule_nodes + [node]

                                for child_node in child_rule_nodes:
                                    for parent_node in parent_rule_nodes:
                                        new_id = new_node_id[0] # Get a new ID
                                        nodes_buff[new_id] = nodes[child_node]
                                        new_node_id = new_node_id[1:] # Del this ID from id list

                                        edges_buff[new_id] = [[],[]]
                                        edges_buff[new_id][1] = edges[child_node][1] + edges[parent_node][1]
                                        edges_buff[new_id][1].remove(node)
                                        edges_buff[new_id][1] = list(dict.fromkeys(edges_buff[new_id][1]))
                                        edges_buff[new_id][0] = edges[child_node][0]

                                # analyzed_nodes += new_node_id
                                flag = True

                                # Del old nodes and edges
                                for node_id in new_node_id:
                                    del nodes[node_id]
                                    del edges[node_id]
                                    analyzed_nodes += [node_id]

                                for node_id in nodes_buff:
                                    del nodes[node_id]
                                    del edges[node_id]
                                
                                break

            if(flag):                
                # Make changes in graph
                nodes.update(nodes_buff)
                edges.update(edges_buff)


                for node in nodes_buff:
                    for parent_node in edges_buff[node][1]:
                        for child_node in edges[parent_node][0]:
                            if(child_node not in nodes):
                                edges[parent_node][0].remove(child_node)
                        if(node not in edges[parent_node][0]):
                            edges[parent_node][0].append(node)

                    for child_node in edges_buff[node][0]:
                        for parent_node in edges[child_node][1]:
                            if(parent_node not in nodes):
                                edges[child_node][1].remove(parent_node)
                        if(node not in edges[child_node][1]):
                            edges[child_node][1].append(node)
                
                nodes_to_analyse = [ele for ele in nodes_to_analyse if ele not in analyzed_nodes]
                #nodes_to_analyse = list(nodes_to_analyse_buff) # Del analysed nodes from nodes_to_analyse
                flag = False
            else:
                break

        # Reorder ID
        match = {}
        nodes_save = dict(nodes)
        edges_save = dict(edges)
        nodes = {}
        edges = {}
        current_id = 1

        for node in nodes_save:
            match[node] = str(current_id)
            nodes[str(current_id)] = nodes_save[node]
            current_id += 1

        for node in edges_save:
            edges[match[node]] = [[], []]
            for child_node in edges_save[node][0]:
                edges[match[node]][0] += [match[child_node]]
            for parent_node in edges_save[node][1]:
                edges[match[node]][1] += [match[parent_node]]


        # Save Graph
        node_file.close()
        edge_file.close()
        node_file = open(self.working_dir + "VERTICES.CSV", "w")
        edge_file = open(self.working_dir + "ARCS.CSV", "w")

        for node in nodes:
            pred = nodes[node].split('(')[0]
            if("RULE" in nodes[node]):
                node_type = "AND"
                prob = "0"
            elif(pred in allowed_literals or pred in disallowed_literals):
                node_type = "OR"
                prob = "0"
            else:
                node_type = "LEAF"
                prob = "1"
                
            node_file.write(node + ",\"" + nodes[node] + "\",\"" + node_type + "\"," + prob + "\n")


        for node in edges:
            for child_node in edges[node][0]:
                edge_file.write(child_node + "," + node + ",-1\n")
            


    def parseConfigFile(self):
        f = open(self.config_file_path)
        content_file = f.read()
        self.config = json.loads(content_file)


    def datetimeToRound(self, date):
        date_days = self.config["start"].split(' ')[0]
        date_sec = self.config["start"].split(' ')[1]

        year, mounth, day = date_days.split('-')
        hour, min, sec = date_sec.split(':')

        start_date = datetime.datetime(int(year), int(mounth), int(day), int(hour), int(min), int(sec))

        duration = date - start_date

        days, seconds = duration.days, duration.seconds
        hours = days * 24 + seconds // 3600
        minutes = (seconds % 3600) // 60
        seconds = seconds % 60

        if (self.config["timeUnit"] == "day"):
            return days
        elif (self.config["timeUnit"] == "hour"):
            return hours
        elif (self.config["timeUnit"] == "minute"):
            return hours * 60 + minutes
        elif (self.config["timeUnit"] == "second"):
            return hours * 3600 + minutes * 60 + seconds





if __name__ == "__main__" :
    print("Generation of Dynamic Attack Graph GEneRator - DAGGER")
    calculator = RiskPropagationCalculator(sys.argv[1])
