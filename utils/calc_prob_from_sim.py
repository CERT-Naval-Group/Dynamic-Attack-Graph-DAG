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
from os import listdir
from os.path import isfile, join



def genRes(files_path):
    flag = True
    res = []
    nb_files = len(files_path)
    
    for file_path in files_path:
        with open(file_path, 'r') as csvfile:
            csvreader = csv.reader(csvfile)

            if(flag):
                for row in csvreader:
                    line_buffer = []
                    for col in row:
                        line_buffer += [int(col)]
                    res += [line_buffer]   
                flag = False
            else:
                i = 0
                for row in csvreader:
                    for j in range(0, len(res[i])):
                        res[i][j] += int(row[j])

                    i += 1
                    
    for i in range(0, len(res)):
        for j in range(0, len(res[i])):
            res[i][j] = round(res[i][j] / nb_files, 3)


    with open('sim_res.txt', 'w') as f:
        writer = csv.writer(f)

        for row in res:
            writer.writerow(row)


if __name__ == "__main__" :
    dir_path = sys.argv[1]
    files_path = [dir_path + f for f in listdir(dir_path) if isfile(join(dir_path, f))]
    genRes(files_path)
    
