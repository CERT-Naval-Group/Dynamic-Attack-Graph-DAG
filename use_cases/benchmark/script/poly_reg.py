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


import numpy
import matplotlib.pyplot as plt
from sklearn.metrics import r2_score



print("\n")
print("--------------------------------------------------")
print("Evolution of the exuction time of the simulation algorithm by the number of hosts")
print("--------------------------------------------------")


x = []
y = []

file_host = open("benchmark_res_release_nb_host_without_opti.txt", 'r')
lines = file_host.readlines()

for line in lines:
    splitted_line = line[:-1].split('\t')
    x += [int(splitted_line[0])]
    y += [float(splitted_line[-1])]


polynome = numpy.polyfit(x, y, 1)
print("polynomial for nb_host : " + str(polynome))

mymodel = numpy.poly1d(polynome)

time = mymodel(10000)
print("Prediction for the execution time with 10.000 hosts on the network : " + str(time) + " seconds")

print("r-squared : " + str(r2_score(y, mymodel(x)))) 

myline = numpy.linspace(1, x[-1]+500, x[-1]+500)

plt.scatter(x, y)
plt.plot(myline, mymodel(myline), color="red")
plt.show()


print("\n")
print("--------------------------------------------------")
print("Evolution of the exuction time of the simulation algorithm by the attack graph size")
print("--------------------------------------------------")


x = []
y = []

for line in lines:
    splitted_line = line[:-1].split('\t')
    x += [int(splitted_line[2])]
    y += [float(splitted_line[-1])]

polynome = numpy.polyfit(x, y, 1)
print("polynomial for nb_host : " + str(polynome))

mymodel = numpy.poly1d(polynome)

time = mymodel(200100008)
print("Prediction for the execution time with 100.000.000 nodes in the attack graph : " + str(time) + " seconds")

print("r-squared : " + str(r2_score(y, mymodel(x))))

myline = numpy.linspace(1, x[-1]+500, x[-1]+500)

plt.scatter(x, y)
plt.plot(myline, mymodel(myline), color="red")
plt.show()



print("\n")
print("--------------------------------------------------")
print("Evolution of the exuction time of the MulVAL algorithm by the number of hosts")
print("--------------------------------------------------")


x = []
y = []

for line in lines:
    splitted_line = line[:-1].split('\t')
    x += [int(splitted_line[0])]
    y += [float(splitted_line[-2])]

polynome = numpy.polyfit(x, y, 2)
print("polynomial for nb_host : " + str(polynome))

mymodel = numpy.poly1d(polynome)

time = mymodel(10000)
print("Prediction for the execution time with 10.000 hosts on the network : " + str(time) + " seconds")

print("r-squared : " + str(r2_score(y, mymodel(x))))

myline = numpy.linspace(1, x[-1]+500, x[-1]+500)

plt.scatter(x, y)
plt.plot(myline, mymodel(myline), color="red")
plt.show()


print("\n")
print("--------------------------------------------------")
print("Evolution of the attack graph size by the number of hosts")
print("--------------------------------------------------")


x = []
y = []

for line in lines:
    splitted_line = line[:-1].split('\t')
    x += [int(splitted_line[0])]
    y += [float(splitted_line[2])]

polynome = numpy.polyfit(x, y, 1)
print("polynomial for nb_host : " + str(polynome))

mymodel = numpy.poly1d(polynome)

time = mymodel(10000)
print("Prediction for the attack graph size with 10.000 hosts on the network : " + str(int(time)) + " nodes")

print("r-squared : " + str(r2_score(y, mymodel(x))))

myline = numpy.linspace(1, x[-1]+500, x[-1]+500)

plt.scatter(x, y)
plt.plot(myline, mymodel(myline), color="red")
plt.show()



print("\n")
print("--------------------------------------------------")
print("Evolution of the exuction time of the MulVAL algorithm in relation to the attack graph size")
print("--------------------------------------------------")


x = []
y = []

for line in lines:
    splitted_line = line[:-1].split('\t')
    x += [int(splitted_line[2])]
    y += [float(splitted_line[3])]

polynome = numpy.polyfit(x, y, 2)
print("polynomial for nb_host : " + str(polynome))

mymodel = numpy.poly1d(polynome)

time = mymodel(1000000)
print("Prediction for the loading time with 1.000.000 nodes in the attack graph : " + str(time) + " seconds")

print("r-squared : " + str(r2_score(y, mymodel(x))))

myline = numpy.linspace(1, x[-1]+500, x[-1]+500)

plt.scatter(x, y)
plt.plot(myline, mymodel(myline), color="red")
plt.show()




print("\n")
print("--------------------------------------------------")
print("Evolution of the exuction time of the simulation algorithm by the number of vulnerability")
print("--------------------------------------------------")


x = []
y = []

file_host = open("benchmark_res_release_nb_vuln_without_opti.txt", 'r')
lines = file_host.readlines()

for line in lines:
    splitted_line = line[:-1].split('\t')
    x += [int(splitted_line[0])]
    y += [float(splitted_line[-1])]


polynome = numpy.polyfit(x, y, 1)
print("polynomial for nb_vuln : " + str(polynome))

mymodel = numpy.poly1d(polynome)

time = mymodel(1000)
print("Prediction for the execution time with 1.000 vuln on the network : " + str(time) + " seconds")

print("r-squared : " + str(r2_score(y, mymodel(x))))

myline = numpy.linspace(1, x[-1]+500, x[-1]+500)

plt.scatter(x, y)
plt.plot(myline, mymodel(myline), color="red")
plt.show()


print("\n")
print("--------------------------------------------------")
print("Evolution of the exuction time of the algorithm MulVAL by the number of vulnerability")
print("--------------------------------------------------")


x = []
y = []

for line in lines:
    splitted_line = line[:-1].split('\t')
    x += [int(splitted_line[0])]
    y += [float(splitted_line[-2])]

polynome = numpy.polyfit(x, y, 1)
print("polynomial for nb_vuln : " + str(polynome))

mymodel = numpy.poly1d(polynome)

time = mymodel(1000)
print("Prediction for the execution time with 1.000 vuln on the network : " + str(time) + " seconds")

print("r-squared : " + str(r2_score(y, mymodel(x))))

myline = numpy.linspace(1, x[-1]+500, x[-1]+500)

plt.scatter(x, y)
plt.plot(myline, mymodel(myline), color="red")
plt.show()



print("\n")
print("--------------------------------------------------")
print("Attack graph size in relation to the number of vulnerabilities")
print("--------------------------------------------------")


x = []
y = []

for line in lines:
    splitted_line = line[:-1].split('\t')
    x += [int(splitted_line[0])]
    y += [float(splitted_line[2])]

polynome = numpy.polyfit(x, y, 1)
print("polynomial for nb_vuln : " + str(polynome))

mymodel = numpy.poly1d(polynome)

time = mymodel(1000)
print("Prediction for the execution time with 1.000 vuln on the network : " + str(time) + " seconds")

print("r-squared : " + str(r2_score(y, mymodel(x))))

myline = numpy.linspace(1, x[-1]+500, x[-1]+500)

plt.scatter(x, y)
plt.plot(myline, mymodel(myline), color="red")
plt.show()


























print("\n")
print("--------------------------------------------------")
print("Evolution of the exuction time of the simulation algorithm by the number of hosts (with optimization)")
print("--------------------------------------------------")


x = []
y = []

file_host = open("benchmark_res_release_nb_host_with_opti.txt", 'r')
lines = file_host.readlines()

for line in lines:
    splitted_line = line[:-1].split('\t')
    x += [int(splitted_line[0])]
    y += [float(splitted_line[-1])]


polynome = numpy.polyfit(x, y, 1)
print("polynomial for nb_host : " + str(polynome))

mymodel = numpy.poly1d(polynome)

time = mymodel(10000)
print("Prediction for the execution time with 10.000 hosts on the network : " + str(time) + " seconds")

print("r-squared : " + str(r2_score(y, mymodel(x)))) 

myline = numpy.linspace(1, x[-1]+500, x[-1]+500)

plt.scatter(x, y)
plt.plot(myline, mymodel(myline), color="red")
plt.show()


print("\n")
print("--------------------------------------------------")
print("Evolution of the exuction time of the simulation algorithm by the attack graph size (with optimization)")
print("--------------------------------------------------")


x = []
y = []

for line in lines:
    splitted_line = line[:-1].split('\t')
    x += [int(splitted_line[2])]
    y += [float(splitted_line[-1])]

polynome = numpy.polyfit(x, y, 1)
print("polynomial for nb_host : " + str(polynome))

mymodel = numpy.poly1d(polynome)

time = mymodel(200100008)
print("Prediction for the execution time with 100.000.000 nodes in the attack graph : " + str(time) + " seconds")

print("r-squared : " + str(r2_score(y, mymodel(x))))

myline = numpy.linspace(1, x[-1]+500, x[-1]+500)

plt.scatter(x, y)
plt.plot(myline, mymodel(myline), color="red")
plt.show()



print("\n")
print("--------------------------------------------------")
print("Evolution of the exuction time of the MulVAL algorithm by the number of hosts (with optimization)")
print("--------------------------------------------------")


x = []
y = []

for line in lines:
    splitted_line = line[:-1].split('\t')
    x += [int(splitted_line[0])]
    y += [float(splitted_line[-2])]

polynome = numpy.polyfit(x, y, 2)
print("polynomial for nb_host : " + str(polynome))

mymodel = numpy.poly1d(polynome)

time = mymodel(10000)
print("Prediction for the execution time with 10.000 hosts on the network : " + str(time) + " seconds")

print("r-squared : " + str(r2_score(y, mymodel(x))))

myline = numpy.linspace(1, x[-1]+500, x[-1]+500)

plt.scatter(x, y)
plt.plot(myline, mymodel(myline), color="red")
plt.show()


print("\n")
print("--------------------------------------------------")
print("Evolution of the attack graph size by the number of hosts (with optimization)")
print("--------------------------------------------------")


x = []
y = []

for line in lines:
    splitted_line = line[:-1].split('\t')
    x += [int(splitted_line[0])]
    y += [float(splitted_line[2])]

polynome = numpy.polyfit(x, y, 1)
print("polynomial for nb_host : " + str(polynome))

mymodel = numpy.poly1d(polynome)

time = mymodel(10000)
print("Prediction for the attack graph size with 10.000 hosts on the network : " + str(int(time)) + " nodes")

print("r-squared : " + str(r2_score(y, mymodel(x))))

myline = numpy.linspace(1, x[-1]+500, x[-1]+500)

plt.scatter(x, y)
plt.plot(myline, mymodel(myline), color="red")
plt.show()


print("\n")
print("--------------------------------------------------")
print("Evolution of the optimization time by the number of hosts")
print("--------------------------------------------------")


x = []
y = []

for line in lines:
    splitted_line = line[:-1].split('\t')
    x += [int(splitted_line[0])]
    y += [float(splitted_line[3])]

polynome = numpy.polyfit(x, y, 2)
print("polynomial for nb_host : " + str(polynome))

mymodel = numpy.poly1d(polynome)

time = mymodel(10000)
print("Prediction for the attack graph size with 10.000 hosts on the network : " + str(int(time)) + " nodes")

print("r-squared : " + str(r2_score(y, mymodel(x))))

myline = numpy.linspace(1, x[-1]+500, x[-1]+500)

plt.scatter(x, y)
plt.plot(myline, mymodel(myline), color="red")
plt.show()


print("\n")
print("--------------------------------------------------")
print("Evolution of the exuction time of the simulation algorithm by the number of vulnerability (with optimization)")
print("--------------------------------------------------")


x = []
y = []

file_host = open("benchmark_res_release_nb_vuln_with_opti.txt", 'r')
lines = file_host.readlines()

for line in lines:
    splitted_line = line[:-1].split('\t')
    x += [int(splitted_line[0])]
    y += [float(splitted_line[-1])]


polynome = numpy.polyfit(x, y, 1)
print("polynomial for nb_vuln : " + str(polynome))

mymodel = numpy.poly1d(polynome)

time = mymodel(1000)
print("Prediction for the execution time with 1.000 vuln on the network : " + str(time) + " seconds")

print("r-squared : " + str(r2_score(y, mymodel(x))))

myline = numpy.linspace(1, x[-1]+500, x[-1]+500)

plt.scatter(x, y)
plt.plot(myline, mymodel(myline), color="red")
plt.show()


print("\n")
print("--------------------------------------------------")
print("Evolution of the exuction time of the algorithm MulVAL by the number of vulnerability (with optimization)")
print("--------------------------------------------------")


x = []
y = []

for line in lines:
    splitted_line = line[:-1].split('\t')
    x += [int(splitted_line[0])]
    y += [float(splitted_line[-2])]

polynome = numpy.polyfit(x, y, 1)
print("polynomial for nb_vuln : " + str(polynome))

mymodel = numpy.poly1d(polynome)

time = mymodel(1000)
print("Prediction for the execution time with 1.000 vuln on the network : " + str(time) + " seconds")

print("r-squared : " + str(r2_score(y, mymodel(x))))

myline = numpy.linspace(1, x[-1]+500, x[-1]+500)

plt.scatter(x, y)
plt.plot(myline, mymodel(myline), color="red")
plt.show()



print("\n")
print("--------------------------------------------------")
print("Attack graph size in relation to the number of vulnerabilities [OPTI]")
print("--------------------------------------------------")


x = []
y = []

for line in lines:
    splitted_line = line[:-1].split('\t')
    x += [int(splitted_line[0])]
    y += [float(splitted_line[2])]

polynome = numpy.polyfit(x, y, 1)
print("polynomial for nb_vuln : " + str(polynome))

mymodel = numpy.poly1d(polynome)

time = mymodel(1000)
print("Prediction for the execution time with 1.000 vuln on the network : " + str(time) + " seconds")

print("r-squared : " + str(r2_score(y, mymodel(x))))

myline = numpy.linspace(1, x[-1]+500, x[-1]+500)

plt.scatter(x, y)
plt.plot(myline, mymodel(myline), color="red")
plt.show()
