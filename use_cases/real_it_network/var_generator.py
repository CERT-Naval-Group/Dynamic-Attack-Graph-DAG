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
import json
import copy
import random
import datetime

def printVar(var, min, max, nb_digit):
    res = "["
    for i in range(min, max + 1):
        zero_digits = ""
        for j in range(0, nb_digit - len(str(i))):
            zero_digits += '0'
        res += "'" + var + zero_digits + str(i) + "'" + ", "
    res = res[:-2]
    res += "]"
    return res

def genPCFW10(var_pf_win10, min, number):
    var = "PF-W10-"
    var_pf_win10_pa = "['PF-W10-00001'"
    var_pf_win10_st = "['PF-W10-00002'"
    var_pf_win10_ma = "['PF-W10-00003'"
    var_pf_win10_ly = "['PF-W10-00004'"
    var_pf_win10_br = "['PF-W10-00005'"
    liste = [var_pf_win10_pa, var_pf_win10_st, var_pf_win10_ma, var_pf_win10_ly, var_pf_win10_br]

    for i in range(0, number - min):
        pt = i % 5
        liste[pt] += ", " + genVar(var, min + i + 1, 5)

    print("VAR_PF_W10_PA = " + liste[0] + "]")
    print("VAR_PF_W10_ST = " + liste[1] + "]")
    print("VAR_PF_W10_MA = " + liste[2] + "]")
    print("VAR_PF_W10_LY = " + liste[3] + "]")
    print("VAR_PF_W10_BR = " + liste[4] + "]")



class ModelGeneration():
    def __init__(self, config_file_path, project_config_file_path):
        print("Initialization")

        self.config_file_path = config_file_path
        self.project_config_file_path = project_config_file_path
        self.parseConfigFile()
        self.parseProjectConfigFile()

        self.counter_pc = {"VAR_PF_WIN10": 0, "VAR_PF_WIN7": 0, "VAR_PF_XP": 0, "VAR_PP_WIN10": 0, "VAR_PP_WIN7": 0,
                      "VAR_PP_XP": 0}

        self.var_pc = {
            "VAR_PF": {
                "VAR_PF_WIN10": {"VAR_PF_WIN10_PA": [],
                                 "VAR_PF_WIN10_ST": [],
                                 "VAR_PF_WIN10_MA": [],
                                 "VAR_PF_WIN10_LY": [],
                                 "VAR_PF_WIN10_BR": []
                                 },
                "VAR_PF_WIN7": {"VAR_PF_WIN7_PA": [],
                                "VAR_PF_WIN7_ST": [],
                                "VAR_PF_WIN7_MA": [],
                                "VAR_PF_WIN7_LY": [],
                                "VAR_PF_WIN7_BR": []
                                },
                "VAR_PF_XP": {"VAR_PF_XP_PA": [],
                              "VAR_PF_XP_ST": [],
                              "VAR_PF_XP_MA": [],
                              "VAR_PF_XP_LY": [],
                              "VAR_PF_XP_BR": []
                              }
            },
            "VAR_PP": {
                "VAR_PP_WIN10": {"VAR_PP_WIN10_PA": [],
                                 "VAR_PP_WIN10_ST": [],
                                 "VAR_PP_WIN10_MA": [],
                                 "VAR_PP_WIN10_LY": [],
                                 "VAR_PP_WIN10_BR": []
                                 },
                "VAR_PP_WIN7": {"VAR_PP_WIN7_PA": [],
                                "VAR_PP_WIN7_ST": [],
                                "VAR_PP_WIN7_MA": [],
                                "VAR_PP_WIN7_LY": [],
                                "VAR_PP_WIN7_BR": []
                                },
                "VAR_PP_XP": {"VAR_PP_XP_PA": [],
                              "VAR_PP_XP_ST": [],
                              "VAR_PP_XP_MA": [],
                              "VAR_PP_XP_LY": [],
                              "VAR_PP_XP_BR": []
                              }
            }
        }

        self.counter_ipc = 0

        self.var_ipc = {
            "VAR_IPC_PA_NC": [],
            "VAR_IPC_ST_NC": [],
            "VAR_IPC_MA_NC": [],
            "VAR_IPC_LY_NC": [],
            "VAR_IPC_BR_NC": [],
            "VAR_IPC_PA_C": [],
            "VAR_IPC_ST_C": [],
            "VAR_IPC_MA_C": [],
            "VAR_IPC_LY_C": [],
            "VAR_IPC_BR_C": []
        }



    def parseConfigFile(self):
        f = open(self.config_file_path)
        content_file = f.read()
        self.config = json.loads(content_file)



    def parseProjectConfigFile(self):
        f = open(self.project_config_file_path)
        content_file = f.read()
        self.project_config = json.loads(content_file)



    def genVar(self, var, num, nb_digit):
        res = ""
        zero_digits = ""
        for j in range(0, nb_digit - len(str(num))):
            zero_digits += '0'
        res += var + zero_digits + str(num)
        return res



    def genNVar(self, var_p, var, min, number):
        for i in range(min + 1, number + 1 + min):
            var_p += [self.genVar(var, i, 5)]



    def printVarPC(self):
        varpc_file = open("var_pc.P", 'w')

        var_pc = self.var_pc

        var_pf_win10 = []
        for key in var_pc["VAR_PF"]["VAR_PF_WIN10"].keys():
            varpc_file.write(str(key) + " = " + str(var_pc["VAR_PF"]["VAR_PF_WIN10"][key]) + "\n")
            var_pf_win10 += var_pc["VAR_PF"]["VAR_PF_WIN10"][key]
        varpc_file.write("VAR_PF_WIN10 = " + str(var_pf_win10) + "\n")

        var_pf_win7 = []
        for key in var_pc["VAR_PF"]["VAR_PF_WIN7"].keys():
            varpc_file.write(str(key) + " = " + str(var_pc["VAR_PF"]["VAR_PF_WIN7"][key]) + "\n")
            var_pf_win7 += var_pc["VAR_PF"]["VAR_PF_WIN7"][key]
        varpc_file.write("VAR_PF_WIN7 = " + str(var_pf_win7) + "\n")

        var_pf_xp = []
        for key in var_pc["VAR_PF"]["VAR_PF_XP"].keys():
            varpc_file.write(str(key) + " = " + str(var_pc["VAR_PF"]["VAR_PF_XP"][key]) + "\n")
            var_pf_xp += var_pc["VAR_PF"]["VAR_PF_XP"][key]
        varpc_file.write("VAR_PF_XP = " + str(var_pf_xp) + "\n")

        var_pf = var_pf_win10 + var_pf_win7 + var_pf_xp
        varpc_file.write("VAR_PF = " + str(var_pf) + "\n")

        var_pp_win10 = []
        for key in var_pc["VAR_PP"]["VAR_PP_WIN10"].keys():
            varpc_file.write(str(key) + " = " + str(var_pc["VAR_PP"]["VAR_PP_WIN10"][key]) + "\n")
            var_pp_win10 += var_pc["VAR_PP"]["VAR_PP_WIN10"][key]
        varpc_file.write("VAR_PP_WIN10 = " + str(var_pp_win10) + "\n")

        var_pp_win7 = []
        for key in var_pc["VAR_PP"]["VAR_PP_WIN7"].keys():
            varpc_file.write(str(key) + " = " + str(var_pc["VAR_PP"]["VAR_PP_WIN7"][key]) + "\n")
            var_pp_win7 += var_pc["VAR_PP"]["VAR_PP_WIN7"][key]
        varpc_file.write("VAR_PP_WIN7 = " + str(var_pp_win7) + "\n")

        var_pp_xp = []
        for key in var_pc["VAR_PP"]["VAR_PP_XP"].keys():
            varpc_file.write(str(key) + " = " + str(var_pc["VAR_PP"]["VAR_PP_XP"][key]) + "\n")
            var_pp_xp += var_pc["VAR_PP"]["VAR_PP_XP"][key]
        varpc_file.write("VAR_PP_XP = " + str(var_pp_xp) + "\n")

        var_pp = var_pp_win10 + var_pp_win7 + var_pp_xp
        varpc_file.write("VAR_PP = " + str(var_pp) + "\n")

        var_p = var_pf + var_pp
        varpc_file.write("VAR_P = " + str(var_p) + "\n")

        var_p_pa = var_pc["VAR_PF"]["VAR_PF_WIN10"]["VAR_PF_WIN10_PA"] + var_pc["VAR_PF"]["VAR_PF_WIN7"][
            "VAR_PF_WIN7_PA"] + var_pc["VAR_PF"]["VAR_PF_XP"]["VAR_PF_XP_PA"] + var_pc["VAR_PP"]["VAR_PP_WIN10"][
                       "VAR_PP_WIN10_PA"] + var_pc["VAR_PP"]["VAR_PP_WIN7"]["VAR_PP_WIN7_PA"] + \
                   var_pc["VAR_PP"]["VAR_PP_XP"]["VAR_PP_XP_PA"]
        var_p_st = var_pc["VAR_PF"]["VAR_PF_WIN10"]["VAR_PF_WIN10_ST"] + var_pc["VAR_PF"]["VAR_PF_WIN7"][
            "VAR_PF_WIN7_ST"] + var_pc["VAR_PF"]["VAR_PF_XP"]["VAR_PF_XP_ST"] + var_pc["VAR_PP"]["VAR_PP_WIN10"][
                       "VAR_PP_WIN10_ST"] + var_pc["VAR_PP"]["VAR_PP_WIN7"]["VAR_PP_WIN7_ST"] + \
                   var_pc["VAR_PP"]["VAR_PP_XP"]["VAR_PP_XP_ST"]
        var_p_ma = var_pc["VAR_PF"]["VAR_PF_WIN10"]["VAR_PF_WIN10_MA"] + var_pc["VAR_PF"]["VAR_PF_WIN7"][
            "VAR_PF_WIN7_MA"] + var_pc["VAR_PF"]["VAR_PF_XP"]["VAR_PF_XP_MA"] + var_pc["VAR_PP"]["VAR_PP_WIN10"][
                       "VAR_PP_WIN10_MA"] + var_pc["VAR_PP"]["VAR_PP_WIN7"]["VAR_PP_WIN7_MA"] + \
                   var_pc["VAR_PP"]["VAR_PP_XP"]["VAR_PP_XP_MA"]
        var_p_ly = var_pc["VAR_PF"]["VAR_PF_WIN10"]["VAR_PF_WIN10_LY"] + var_pc["VAR_PF"]["VAR_PF_WIN7"][
            "VAR_PF_WIN7_LY"] + var_pc["VAR_PF"]["VAR_PF_XP"]["VAR_PF_XP_LY"] + var_pc["VAR_PP"]["VAR_PP_WIN10"][
                       "VAR_PP_WIN10_LY"] + var_pc["VAR_PP"]["VAR_PP_WIN7"]["VAR_PP_WIN7_LY"] + \
                   var_pc["VAR_PP"]["VAR_PP_XP"]["VAR_PP_XP_LY"]
        var_p_br = var_pc["VAR_PF"]["VAR_PF_WIN10"]["VAR_PF_WIN10_BR"] + var_pc["VAR_PF"]["VAR_PF_WIN7"][
            "VAR_PF_WIN7_BR"] + var_pc["VAR_PF"]["VAR_PF_XP"]["VAR_PF_XP_BR"] + var_pc["VAR_PP"]["VAR_PP_WIN10"][
                       "VAR_PP_WIN10_BR"] + var_pc["VAR_PP"]["VAR_PP_WIN7"]["VAR_PP_WIN7_BR"] + \
                   var_pc["VAR_PP"]["VAR_PP_XP"]["VAR_PP_XP_BR"]

        varpc_file.write("VAR_P_PA = " + str(var_p_pa) + "\n")
        varpc_file.write("VAR_P_ST = " + str(var_p_pa) + "\n")
        varpc_file.write("VAR_P_MA = " + str(var_p_pa) + "\n")
        varpc_file.write("VAR_P_LY = " + str(var_p_pa) + "\n")
        varpc_file.write("VAR_P_BR = " + str(var_p_pa) + "\n")



    def printVarIPC(self):
        varipc_file = open("var_ipc.P", 'w')

        varipc_file.write("VAR_IPC_PA_NC = " + str(self.var_ipc["VAR_IPC_PA_NC"]) + "\n")
        varipc_file.write("VAR_IPC_ST_NC = " + str(self.var_ipc["VAR_IPC_ST_NC"]) + "\n")
        varipc_file.write("VAR_IPC_MA_NC = " + str(self.var_ipc["VAR_IPC_MA_NC"]) + "\n")
        varipc_file.write("VAR_IPC_LY_NC = " + str(self.var_ipc["VAR_IPC_LY_NC"]) + "\n")
        varipc_file.write("VAR_IPC_BR_NC = " + str(self.var_ipc["VAR_IPC_BR_NC"]) + "\n")

        varipc_file.write("VAR_IPC_PA_C = " + str(self.var_ipc["VAR_IPC_PA_C"]) + "\n")
        varipc_file.write("VAR_IPC_ST_C = " + str(self.var_ipc["VAR_IPC_ST_C"]) + "\n")
        varipc_file.write("VAR_IPC_MA_C = " + str(self.var_ipc["VAR_IPC_MA_C"]) + "\n")
        varipc_file.write("VAR_IPC_LY_C = " + str(self.var_ipc["VAR_IPC_LY_C"]) + "\n")
        varipc_file.write("VAR_IPC_BR_C = " + str(self.var_ipc["VAR_IPC_BR_C"]) + "\n")

        ipc = self.var_ipc["VAR_IPC_PA_NC"] + self.var_ipc["VAR_IPC_ST_NC"] + self.var_ipc["VAR_IPC_MA_NC"] + self.var_ipc["VAR_IPC_LY_NC"] + self.var_ipc["VAR_IPC_BR_NC"] + self.var_ipc["VAR_IPC_PA_C"] + self.var_ipc["VAR_IPC_ST_C"] + self.var_ipc["VAR_IPC_MA_C"] + self.var_ipc["VAR_IPC_LY_C"] + self.var_ipc["VAR_IPC_BR_C"]

        varipc_file.write("VAR_IPC = " + str(ipc) + "\n")



    def printTeleworkingVar(self):
        varipc_file = open("var_pc.P", 'w')

        print("VAR_PNT = " + str(self.var_pnt))
        print("VAR_PT = " + str(self.var_pt))




    def searchVlanHost(self, host, vlan):
        if(host in self.var_pc["VAR_PP"]["VAR_PP_WIN10"]["VAR_PP_WIN10_PA"] or host in self.var_pc["VAR_PP"]["VAR_PP_WIN7"]["VAR_PP_WIN7_PA"] or host in self.var_pc["VAR_PP"]["VAR_PP_XP"]["VAR_PP_XP_PA"]):
            return "'vlan-pa-" + vlan + "'"
        if (host in self.var_pc["VAR_PP"]["VAR_PP_WIN10"]["VAR_PP_WIN10_ST"] or host in
                self.var_pc["VAR_PP"]["VAR_PP_WIN7"]["VAR_PP_WIN7_ST"] or host in self.var_pc["VAR_PP"]["VAR_PP_XP"][
                    "VAR_PP_XP_ST"]):
            return "'vlan-st-" + vlan + "'"
        if (host in self.var_pc["VAR_PP"]["VAR_PP_WIN10"]["VAR_PP_WIN10_MA"] or host in
                self.var_pc["VAR_PP"]["VAR_PP_WIN7"]["VAR_PP_WIN7_MA"] or host in self.var_pc["VAR_PP"]["VAR_PP_XP"][
                    "VAR_PP_XP_MA"]):
            return "'vlan-ma-" + vlan + "'"
        if (host in self.var_pc["VAR_PP"]["VAR_PP_WIN10"]["VAR_PP_WIN10_LY"] or host in
                self.var_pc["VAR_PP"]["VAR_PP_WIN7"]["VAR_PP_WIN7_LY"] or host in self.var_pc["VAR_PP"]["VAR_PP_XP"][
                    "VAR_PP_XP_LY"]):
            return "'vlan-ly-" + vlan + "'"
        if (host in self.var_pc["VAR_PP"]["VAR_PP_WIN10"]["VAR_PP_WIN10_BR"] or host in
                self.var_pc["VAR_PP"]["VAR_PP_WIN7"]["VAR_PP_WIN7_BR"] or host in self.var_pc["VAR_PP"]["VAR_PP_XP"][
                    "VAR_PP_XP_BR"]):
            return "'vlan-br-" + vlan + "'"

        if (host in self.var_pc["VAR_PF"]["VAR_PF_WIN10"]["VAR_PF_WIN10_PA"] or host in
                self.var_pc["VAR_PF"]["VAR_PF_WIN7"]["VAR_PF_WIN7_PA"] or host in self.var_pc["VAR_PF"]["VAR_PF_XP"][
                    "VAR_PF_XP_PA"]):
            return "'vlan-pa-" + vlan + "'"
        if (host in self.var_pc["VAR_PF"]["VAR_PF_WIN10"]["VAR_PF_WIN10_ST"] or host in
                self.var_pc["VAR_PF"]["VAR_PF_WIN7"]["VAR_PF_WIN7_ST"] or host in self.var_pc["VAR_PF"]["VAR_PF_XP"][
                    "VAR_PF_XP_ST"]):
            return "'vlan-st-" + vlan + "'"
        if (host in self.var_pc["VAR_PF"]["VAR_PF_WIN10"]["VAR_PF_WIN10_MA"] or host in
                self.var_pc["VAR_PF"]["VAR_PF_WIN7"]["VAR_PF_WIN7_MA"] or host in self.var_pc["VAR_PF"]["VAR_PF_XP"][
                    "VAR_PF_XP_MA"]):
            return "'vlan-ma-" + vlan + "'"
        if (host in self.var_pc["VAR_PF"]["VAR_PF_WIN10"]["VAR_PF_WIN10_LY"] or host in
                self.var_pc["VAR_PF"]["VAR_PF_WIN7"]["VAR_PF_WIN7_LY"] or host in self.var_pc["VAR_PF"]["VAR_PF_XP"][
                    "VAR_PF_XP_LY"]):
            return "'vlan-ly-" + vlan + "'"
        if (host in self.var_pc["VAR_PF"]["VAR_PF_WIN10"]["VAR_PF_WIN10_BR"] or host in
                self.var_pc["VAR_PF"]["VAR_PF_WIN7"]["VAR_PF_WIN7_BR"] or host in self.var_pc["VAR_PF"]["VAR_PF_XP"][
                    "VAR_PF_XP_BR"]):
            return "'vlan-br-" + vlan + "'"


    def genDate(self, current_date):
        return (current_date.strftime("%Y") + "-" + current_date.strftime("%m") + "-" + current_date.strftime("%d") + " 00:00:00", current_date.strftime("%Y") + "-" + current_date.strftime("%m") + "-" + current_date.strftime("%d") + " 23:59:59")


    def printTeleworkingStatements(self):
        pc_file = open("pc.P", 'w')
        
        start_date_list = self.project_config["start"].replace(' ', '-').replace(':', '-').split('-')
        end_date_list = self.project_config["end"].replace(' ', '-').replace(':', '-').split('-')

        start_date = datetime.datetime(int(start_date_list[0]), int(start_date_list[1]), int(start_date_list[2]),
                          int(start_date_list[3]), int(start_date_list[4]), int(start_date_list[5]))
        end_date = datetime.datetime(int(end_date_list[0]), int(end_date_list[1]), int(end_date_list[2]), int(end_date_list[3]), int(end_date_list[4]), int(end_date_list[5]))

        pc_file.write("networkServiceInfo(VAR_P, _, 'win-rpc-mapper', rpc, 135, root).[(2021-01-04 00:00:00,2021-01-10 23:59:59,1)]" + "\n")
        pc_file.write("networkServiceInfo(VAR_P, _, 'win-139-server', tcp, 139, root).[(2021-01-04 00:00:00,2021-01-10 23:59:59,1)]" + "\n")
        pc_file.write("networkServiceInfo(VAR_P, _, 'win-smb-server', smb, 445, root).[(2021-01-04 00:00:00,2021-01-10 23:59:59,1)]" + "\n")


        for host in self.var_pnt:
            rng = random.uniform(0, 1)
            if(rng < (self.config["vlan"]["adm"] / 100)):
                vlan_host = self.searchVlanHost(host, "100")
            elif(rng < (self.config["vlan"]["user"] / 100)):
                vlan_host = self.searchVlanHost(host, "300")
            else:
            	vlan_host = self.searchVlanHost(host, "200")
            	
            pc_file.write("vlanInterface('" + host + "', " + vlan_host + ").[(" + str(start_date) + "," + str(end_date) + ",1)]" + "\n")


        for host in self.teleworkingStatements.keys():
            dates_nt = []
            dates_t = []
            vlan_host = self.searchVlanHost(host, "300")
            days = self.teleworkingStatements[host]
            current_date = start_date
            i = 0
            while(current_date <= end_date):
                if (days[i] == 0):
                    dates_nt.append(self.genDate(current_date))
                else:
                    dates_t.append(self.genDate(current_date))
                i += 1
                current_date += datetime.timedelta(days=1)

            dates_nt_str = "["
            for date_tuple in dates_nt:
                dates_nt_str += "("
                dates_nt_str += date_tuple[0]
                dates_nt_str += ","
                dates_nt_str += date_tuple[1]
                dates_nt_str += ",1),"
            dates_nt_str = dates_nt_str[:-1]
            dates_nt_str += "]"

            dates_t_str = "["
            for date_tuple in dates_t:
                dates_t_str += "("
                dates_t_str += date_tuple[0]
                dates_t_str += ","
                dates_t_str += date_tuple[1]
                dates_t_str += ",1),"
            dates_t_str = dates_t_str[:-1]
            dates_t_str += "]"

            pc_file.write("vlanInterface('" + host + "', " + vlan_host + ")." + dates_nt_str + "\n")
            pc_file.write("vlanInterface('" + host + "', 'homeNetwork_" + host.replace("-", "") + "')." + dates_t_str + "\n")
            pc_file.write("attackerLocated('homeNetwork_" + host.replace("-", "") + "').[(2021-01-04 00:00:00,2021-01-10 23:59:59,0.01)]\n")
            
            if("-pa-" in vlan_host):
            	pc_file.write("vlanInterface('" + host + "', 'vlan-pa-700')." + dates_t_str + "\n")
            elif("-st-" in vlan_host):
            	pc_file.write("vlanInterface('" + host + "', 'vlan-st-700')." + dates_t_str + "\n")
            elif("-ma-" in vlan_host):
            	pc_file.write("vlanInterface('" + host + "', 'vlan-ma-700')." + dates_t_str + "\n")
            elif("-ly-" in vlan_host):
            	pc_file.write("vlanInterface('" + host + "', 'vlan-ly-700')." + dates_t_str + "\n")
            elif("-br-" in vlan_host):
            	pc_file.write("vlanInterface('" + host + "', 'vlan-br-700')." + dates_t_str + "\n")



    def genTeleworkingStatements(self):
        self.teleworkingStatements = {}
        for host in self.var_pt:
            days = [0,0,0,0,0,0,0]
            j = int(random.uniform(0,7))
            for i in range (j, j + self.config["teleworking"]["daysPerWeek"]):
                days[i%7] = 1

            self.teleworkingStatements[host] = days



    def genTeleworkingVar(self):
        self.var_pnt = []
        self.var_pt = []

        copy.deepcopy(self.var_pc["VAR_PF"])
        for key in self.var_pc["VAR_PF"].keys():
            for key2 in self.var_pc["VAR_PF"][key].keys():
                for elem in self.var_pc["VAR_PF"][key][key2]:
                    self.var_pnt.append(elem)

        var_pp = []

        for key in self.var_pc["VAR_PP"].keys():
            for key2 in self.var_pc["VAR_PP"][key].keys():
                for elem in self.var_pc["VAR_PP"][key][key2]:
                    var_pp.append(elem)

        for pc in var_pp:
            if((self.config["teleworking"]["percent"] / 100) > random.uniform(0, 1)):
                self.var_pt.append(pc)
            else:
                self.var_pnt.append(pc)



    def genIPCVar(self):
        number = self.config["count"]["IPC"]["IPC_PA_NC"]
        self.genNVar(self.var_ipc["VAR_IPC_PA_NC"], "IPC-",
                     self.counter_ipc, number)
        self.counter_ipc += number
        number = self.config["count"]["IPC"]["IPC_ST_NC"]
        self.genNVar(self.var_ipc["VAR_IPC_ST_NC"], "IPC-",
                     self.counter_ipc, number)
        self.counter_ipc += number
        number = self.config["count"]["IPC"]["IPC_MA_NC"]
        self.genNVar(self.var_ipc["VAR_IPC_MA_NC"], "IPC-",
                     self.counter_ipc, number)
        self.counter_ipc += number
        number = self.config["count"]["IPC"]["IPC_LY_NC"]
        self.genNVar(self.var_ipc["VAR_IPC_LY_NC"], "IPC-",
                     self.counter_ipc, number)
        self.counter_ipc += number
        number = self.config["count"]["IPC"]["IPC_BR_NC"]
        self.genNVar(self.var_ipc["VAR_IPC_BR_NC"], "IPC-",
                     self.counter_ipc, number)
        self.counter_ipc += number

        number = self.config["count"]["IPC"]["IPC_PA_C"]
        self.genNVar(self.var_ipc["VAR_IPC_PA_C"], "IPC-",
                     self.counter_ipc, number)
        self.counter_ipc += number
        number = self.config["count"]["IPC"]["IPC_ST_C"]
        self.genNVar(self.var_ipc["VAR_IPC_ST_C"], "IPC-",
                     self.counter_ipc, number)
        self.counter_ipc += number
        number = self.config["count"]["IPC"]["IPC_MA_C"]
        self.genNVar(self.var_ipc["VAR_IPC_MA_C"], "IPC-",
                     self.counter_ipc, number)
        self.counter_ipc += number
        number = self.config["count"]["IPC"]["IPC_LY_C"]
        self.genNVar(self.var_ipc["VAR_IPC_LY_C"], "IPC-",
                     self.counter_ipc, number)
        self.counter_ipc += number
        number = self.config["count"]["IPC"]["IPC_BR_C"]
        self.genNVar(self.var_ipc["VAR_IPC_BR_C"], "IPC-",
                     self.counter_ipc, number)
        self.counter_ipc += number


    def genPCVar(self):

        number = self.config["count"]["PC"]["PF_WIN10_PA"]
        self.genNVar(self.var_pc["VAR_PF"]["VAR_PF_WIN10"]["VAR_PF_WIN10_PA"], "PF-WIN10-", self.counter_pc["VAR_PF_WIN10"], number)
        self.counter_pc["VAR_PF_WIN10"] += number
        number = self.config["count"]["PC"]["PF_WIN10_ST"]
        self.genNVar(self.var_pc["VAR_PF"]["VAR_PF_WIN10"]["VAR_PF_WIN10_ST"], "PF-WIN10-", self.counter_pc["VAR_PF_WIN10"], number)
        self.counter_pc["VAR_PF_WIN10"] += number
        number = self.config["count"]["PC"]["PF_WIN10_MA"]
        self.genNVar(self.var_pc["VAR_PF"]["VAR_PF_WIN10"]["VAR_PF_WIN10_MA"], "PF-WIN10-", self.counter_pc["VAR_PF_WIN10"], number)
        self.counter_pc["VAR_PF_WIN10"] += number
        number = self.config["count"]["PC"]["PF_WIN10_LY"]
        self.genNVar(self.var_pc["VAR_PF"]["VAR_PF_WIN10"]["VAR_PF_WIN10_LY"], "PF-WIN10-", self.counter_pc["VAR_PF_WIN10"], number)
        self.counter_pc["VAR_PF_WIN10"] += number
        number = self.config["count"]["PC"]["PF_WIN10_BR"]
        self.genNVar(self.var_pc["VAR_PF"]["VAR_PF_WIN10"]["VAR_PF_WIN10_BR"], "PF-WIN10-", self.counter_pc["VAR_PF_WIN10"], number)
        self.counter_pc["VAR_PF_WIN10"] += number

        number = self.config["count"]["PC"]["PF_WIN7_PA"]
        self.genNVar(self.var_pc["VAR_PF"]["VAR_PF_WIN7"]["VAR_PF_WIN7_PA"], "PF-WIN7-", self.counter_pc["VAR_PF_WIN7"], number)
        self.counter_pc["VAR_PF_WIN7"] += number
        number = self.config["count"]["PC"]["PF_WIN7_ST"]
        self.genNVar(self.var_pc["VAR_PF"]["VAR_PF_WIN7"]["VAR_PF_WIN7_ST"], "PF-WIN7-", self.counter_pc["VAR_PF_WIN7"], number)
        self.counter_pc["VAR_PF_WIN7"] += number
        number = self.config["count"]["PC"]["PF_WIN7_MA"]
        self.genNVar(self.var_pc["VAR_PF"]["VAR_PF_WIN7"]["VAR_PF_WIN7_MA"], "PF-WIN7-", self.counter_pc["VAR_PF_WIN7"], number)
        self.counter_pc["VAR_PF_WIN7"] += number
        number = self.config["count"]["PC"]["PF_WIN7_LY"]
        self.genNVar(self.var_pc["VAR_PF"]["VAR_PF_WIN7"]["VAR_PF_WIN7_LY"], "PF-WIN7-", self.counter_pc["VAR_PF_WIN7"], number)
        self.counter_pc["VAR_PF_WIN7"] += number
        number = self.config["count"]["PC"]["PF_WIN7_BR"]
        self.genNVar(self.var_pc["VAR_PF"]["VAR_PF_WIN7"]["VAR_PF_WIN7_BR"], "PF-WIN7-", self.counter_pc["VAR_PF_WIN7"], number)
        self.counter_pc["VAR_PF_WIN7"] += number

        number = self.config["count"]["PC"]["PF_XP_PA"]
        self.genNVar(self.var_pc["VAR_PF"]["VAR_PF_XP"]["VAR_PF_XP_PA"], "PF-XP-", self.counter_pc["VAR_PF_XP"], number)
        self.counter_pc["VAR_PF_XP"] += number
        number = self.config["count"]["PC"]["PF_XP_ST"]
        self.genNVar(self.var_pc["VAR_PF"]["VAR_PF_XP"]["VAR_PF_XP_ST"], "PF-XP-", self.counter_pc["VAR_PF_XP"], number)
        self.counter_pc["VAR_PF_XP"] += number
        number = self.config["count"]["PC"]["PF_XP_MA"]
        self.genNVar(self.var_pc["VAR_PF"]["VAR_PF_XP"]["VAR_PF_XP_MA"], "PF-XP-", self.counter_pc["VAR_PF_XP"], number)
        self.counter_pc["VAR_PF_XP"] += number
        number = self.config["count"]["PC"]["PF_XP_LY"]
        self.genNVar(self.var_pc["VAR_PF"]["VAR_PF_XP"]["VAR_PF_XP_LY"], "PF-XP-", self.counter_pc["VAR_PF_XP"], number)
        self.counter_pc["VAR_PF_XP"] += number
        number = self.config["count"]["PC"]["PF_XP_BR"]
        self.genNVar(self.var_pc["VAR_PF"]["VAR_PF_XP"]["VAR_PF_XP_BR"], "PF-XP-", self.counter_pc["VAR_PF_XP"], number)
        self.counter_pc["VAR_PF_XP"] += number

        number = self.config["count"]["PC"]["PP_WIN10_PA"]
        self.genNVar(self.var_pc["VAR_PP"]["VAR_PP_WIN10"]["VAR_PP_WIN10_PA"], "PP-WIN10-",
                   self.counter_pc["VAR_PP_WIN10"], number)
        self.counter_pc["VAR_PP_WIN10"] += number
        number = self.config["count"]["PC"]["PP_WIN10_ST"]
        self.genNVar(self.var_pc["VAR_PP"]["VAR_PP_WIN10"]["VAR_PP_WIN10_ST"], "PP-WIN10-",
                   self.counter_pc["VAR_PP_WIN10"], number)
        self.counter_pc["VAR_PP_WIN10"] += number
        number = self.config["count"]["PC"]["PP_WIN10_MA"]
        self.genNVar(self.var_pc["VAR_PP"]["VAR_PP_WIN10"]["VAR_PP_WIN10_MA"], "PP-WIN10-",
                   self.counter_pc["VAR_PP_WIN10"], number)
        self.counter_pc["VAR_PP_WIN10"] += number
        number = self.config["count"]["PC"]["PP_WIN10_LY"]
        self.genNVar(self.var_pc["VAR_PP"]["VAR_PP_WIN10"]["VAR_PP_WIN10_LY"], "PP-WIN10-",
                   self.counter_pc["VAR_PP_WIN10"], number)
        self.counter_pc["VAR_PP_WIN10"] += number
        number = self.config["count"]["PC"]["PP_WIN10_BR"]
        self.genNVar(self.var_pc["VAR_PP"]["VAR_PP_WIN10"]["VAR_PP_WIN10_BR"], "PP-WIN10-",
                   self.counter_pc["VAR_PP_WIN10"], number)
        self.counter_pc["VAR_PP_WIN10"] += number

        number = self.config["count"]["PC"]["PP_WIN7_PA"]
        self.genNVar(self.var_pc["VAR_PP"]["VAR_PP_WIN7"]["VAR_PP_WIN7_PA"], "PP-WIN7-", self.counter_pc["VAR_PP_WIN7"],
                   number)
        self.counter_pc["VAR_PP_WIN7"] += number
        number = self.config["count"]["PC"]["PP_WIN7_ST"]
        self.genNVar(self.var_pc["VAR_PP"]["VAR_PP_WIN7"]["VAR_PP_WIN7_ST"], "PP-WIN7-", self.counter_pc["VAR_PP_WIN7"],
                   number)
        self.counter_pc["VAR_PP_WIN7"] += number
        number = self.config["count"]["PC"]["PP_WIN7_MA"]
        self.genNVar(self.var_pc["VAR_PP"]["VAR_PP_WIN7"]["VAR_PP_WIN7_MA"], "PP-WIN7-", self.counter_pc["VAR_PP_WIN7"],
                   number)
        self.counter_pc["VAR_PP_WIN7"] += number
        number = self.config["count"]["PC"]["PP_WIN7_LY"]
        self.genNVar(self.var_pc["VAR_PP"]["VAR_PP_WIN7"]["VAR_PP_WIN7_LY"], "PP-WIN7-", self.counter_pc["VAR_PP_WIN7"],
                   number)
        self.counter_pc["VAR_PP_WIN7"] += number
        number = self.config["count"]["PC"]["PP_WIN7_BR"]
        self.genNVar(self.var_pc["VAR_PP"]["VAR_PP_WIN7"]["VAR_PP_WIN7_BR"], "PP-WIN7-", self.counter_pc["VAR_PP_WIN7"],
                   number)
        self.counter_pc["VAR_PP_WIN7"] += number

        number = self.config["count"]["PC"]["PP_XP_PA"]
        self.genNVar(self.var_pc["VAR_PP"]["VAR_PP_XP"]["VAR_PP_XP_PA"], "PP-XP-", self.counter_pc["VAR_PP_XP"], number)
        self.counter_pc["VAR_PP_XP"] += number
        number = self.config["count"]["PC"]["PP_XP_ST"]
        self.genNVar(self.var_pc["VAR_PP"]["VAR_PP_XP"]["VAR_PP_XP_ST"], "PP-XP-", self.counter_pc["VAR_PP_XP"], number)
        self.counter_pc["VAR_PP_XP"] += number
        number = self.config["count"]["PC"]["PP_XP_MA"]
        self.genNVar(self.var_pc["VAR_PP"]["VAR_PP_XP"]["VAR_PP_XP_MA"], "PP-XP-", self.counter_pc["VAR_PP_XP"], number)
        self.counter_pc["VAR_PP_XP"] += number
        number = self.config["count"]["PC"]["PP_XP_LY"]
        self.genNVar(self.var_pc["VAR_PP"]["VAR_PP_XP"]["VAR_PP_XP_LY"], "PP-XP-", self.counter_pc["VAR_PP_XP"], number)
        self.counter_pc["VAR_PP_XP"] += number
        number = self.config["count"]["PC"]["PP_XP_BR"]
        self.genNVar(self.var_pc["VAR_PP"]["VAR_PP_XP"]["VAR_PP_XP_BR"], "PP-XP-", self.counter_pc["VAR_PP_XP"], number)
        self.counter_pc["VAR_PP_XP"] += number



if __name__ == "__main__" :
    config_file_path = sys.argv[1]
    project_config_file_path = sys.argv[2]
    var = ModelGeneration(config_file_path, project_config_file_path)
    print("Generation ...")
    var.genPCVar()
    var.printVarPC()
    var.genIPCVar()
    var.printVarIPC()
    var.genTeleworkingVar()
    #var.printTeleworkingVar()
    var.genTeleworkingStatements()
    var.printTeleworkingStatements()
