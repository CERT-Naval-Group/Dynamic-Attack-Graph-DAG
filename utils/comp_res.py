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



def compRes(file_path1, file_path2):
    res = []
    
    with open(file_path1, 'r') as csvfile1:
        csvreader1 = csv.reader(csvfile1)
        with open(file_path2, 'r') as csvfile2:
            csvreader2 = csv.reader(csvfile2)

            i = 0
            for row1 in csvreader1:
                row2 = next(csvreader2)
                buff_row = []
                for j in range(0, len(row1)):
                    buff_row += [float(row2[j]) - float(row1[j])]

                res += [buff_row]
                i += 1

    with open('comp_res.txt', 'w') as f:
        writer = csv.writer(f)

        for row in res:
            writer.writerow(row)
            



if __name__ == "__main__" :
    file_path1 = sys.argv[1]
    file_path2 = sys.argv[2]
    compRes(file_path1, file_path2)
