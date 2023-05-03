# Dynamic Attack Graph GEneRator - DAGGER



## Table of Contents
1. [Description](#description)
2. [Installation](#installation)
3. [Usage](#utilisation)
4. [Use cases](#usecases)
5. [References](#références)




## Description <a name="description"></a>

A Dynamic attack graph models the attack paths that a malicious actor can follow in a constantly evolving system.

Simulations are then performed based on the dynamic attack graph to evaluate the attacker's chances of success.

This tool allows you to:

* assess security in complex computer systems composed of thousands of elements.
* consider the changes that take place in the system during its life cycle and the impact on the attacker's offensive strategy.
* take into account the uncertainty on the input values of the model such as the time necessary to carry out an attack
* measure the evolution of the compromise probability of the different components of the system.
* measure the impact of a vulnerability or countermeasure on the security of the system.
* display a heatmap of the system's weaknesses.


The different steps are:
* system modeling, including the list of components and their properties.
* generation of a dynamic attack graph.
* carrying out several attack simulations to calculate the attacker's chances of success.


## Installation <a name="installation"></a>

The script ./install.sh allows you to automatically install:
* all necessary apt and pip3 dependencies.
* retrieve the NVD CVE and MITRE CWE database, and store them in a local MySQL database.
* compile the attack graph generation algorithm and the simulation algorithm.

The installation has been tested on Ubuntu 20.04 and we do not guarantee that the installation works on other distributions.

After installation, the project is copied to the /opt/ directory and a symbolic link is created in the /bin directory to the /opt/utils/dag.sh file.

Here is the structure of the project:
```
dynamic-attack-graph-dag
│   README.md
│   install.sh    
└───core
│   │   makefile
│   │   *.cpp
│   │   *.h
│   └───bin
│   │   └───Release
│   │   │   │   dag.exe
│   │   └───Debug
│   │       │   dag.exe
│   └───obj
│       │   *.o
└───cve-database
│   └───mitre
│   │   └───data
│   │   │   │   mitre_cwe.xml
│   │   └───scripts
│   │   │   │   downloader.sh
│   └───nvd
│   │   └───data
│   │   │   │   *.json
│   │   └───scripts
│   │   │   │   downloader.sh
│   └───scripts
│   │   │   database_feeding.py
└───mulval
│   └───test
│   └───tools
│   │   └───XSB
│   │   └───mulval
│   │   │   └───kb
│   │   │   │   │   optimized_rules.P
└───use_cases
│   └───benchmark
│   │   │   config.json
│   │   └───script
│   │   │   |   benchmark_nb_host.sh
│   │   │   |   benchmark_nb_vuln.sh
│   │   │   |   genRemoteWorkingUseCase.py
│   │   │   |   poly_reg.py
│   │   │   |   sql_feeder_fake_vuln.py
│   │   │   |   sql_query_fake_vuln.txt
│   │   └───timed_input
│   │   │   |   main.P
│   │   │   |   main_template.P
│   └───teleworking
│   │   │   config.json
│   │   └───graph
│   │   │   |   *.png
│   │   └───timed_input
│   │   │   |   main.P
└───utils
│   │   build_graph.py
│   │   build_timed_graph.py
│   │   cvss_to_attack_time.py
│   │   dag.sh
│   │   script.sql
```


## Usage <a name="utilisation"></a>

### Simulation

First of all, you have to go to the directory of the modeled system. An example of a system modeling where a user is working remotly is present in the dynamic-attack-graph-dag/use_cases/teleworking/ directory:

```
$ cd dynamic-attack-graph-dag/use_cases/teleworking/
```

Then you have to edit the configuration file corresponding to the project:

```
$ vim config.json
```


The different parameters that can be configured are

* *start* : Start date of the simulation in the following format AAAA-MM-JJ HH:MM:SS
* *end* : End date of the simulation in the following format AAAA-MM-JJ HH:MM:SS
* *timeUnit* : Incremental step of the simulation. Possible values are: second, minute, hour, day
* *projectName* : Project name
* *timedInputDir* : Path to the directory containing the system description files
* *working_dir* : Path to the project directory
* *database* : Local database connection parameters
  * *host* : IP or host name of the MySQL server
  * *user* : User name
  * *passwd* : User's password. This password is defined when the database is created in file utils/script.sql. It is important to note that this password will also have to be changed in file utils/cvss_to_attack_time.py used to convert the CVSS scores into time of compromise and in file cve-database/scripts/database_feeding.py used to populate the database.
  * *dbName* : Database name
* *stateNodes* : List of litterals that have a memory
* *actions* : List of deduction rules that correspond to the attacker's actions
* *nbSimulations* : Number of simulations to be performed
* *rules_path* : Path to the file containing the deduction rules


For example, in the case of the remote working example, this file looks like this:
```
{
  "start" : "2021-01-04 00:00:00",
  "end": "2021-01-24 23:59:59",
  "timeUnit": "hour",
  "projectName": "teleworking",
  "timedInputDir": "timed_input/",
  "working_dir": "/home/dagsim/dynamic-attack-graph-dag/use_cases/teleworking/",
  "database": {
    "host": "localhost",
    "user": "phpmyadm",
    "passwd": "QRBIhj_ojXoUuzTS65vH",
    "dbName": "rpc"
  },
  "stateNodes": [
    "execCode"
  ],
  "actions": [
    "vulExists"
  ],
  "nbSimulations": 1000,
  "rules_path": "/home/dagsim/dynamic-attack-graph-dag/mulval/tools/mulval/kb/optimized_rules.P",
}
```



The simulation can be started with the following command:

```
$ dagSIM <PATH_TO_CONFIG_FILE>
```

The -g option allows to generate graphs of the evolution of the veracity of the different nodes of the dynamic attack graph. The graphs are stored in the *graphs* directory of the project.

For example:

```
$ dagSIM -g ~/dynamic-attack-graph-dag/use_cases/teleworking/config.json
```


By default, the attack graph is not generated because this operation is too long for complex graphs. If you want to generate a visual rendering of the graph, you have to uncomment lines 288 to 292 of the file mulval/tools/mulval/utils/graph_gen.sh


### Probability calculation


After the execution of the script dagSIM, the result of the simulations is stored in the directory output/. Each file corresponds to the result of a simulation, where each row corresponds to a simulation step and each column corresponds to a node of the attack graph.

It is possible to retrieve the result of several simulations (e.g. in case the simulations were performed on several machines) and to calculate the probability of veracity for each node.

```
$ python3 utils/calc_prob_from_sim.py <PATH_TO_OUTPUT_DIR>
```

For example:

```
$ python3 utils/calc_prob_from_sim.py use_cases/teleworking/output/
```

A file "sim_res.txt" is created in the execution directory of the command and contains the probabilities for the attack graph nodes as a function of time. Each line corresponds to a simulation step and each column corresponds to a node of the attack graph.


### Impact assessment


**Measuring the time to compromise**

It is possible to measure the time required for a node in the attack graph to have a probability greater than a given value.

```
$ python3 utils/get_time_to_compromise.py <PATH_TO_CONFIG_FILE> <PATH_TO_SIM_RES> PROB
```

For example:

```
$ python3 utils/get_time_to_compromise.py use_cases/teleworking/config.json use_cases/teleworking/sim_res/res.txt 0.1
```

A file "ttc.txt" is created in the execution directory of the command and contains the number of time step that are necessary to reach a probability higher than PROB for each node of the attack graph.
The time step depends on the "timeUnit" parameter that is set in the project configuration file. This file can be used to display a heatmap of the system's weaknesses.


**Comparison of simulations**

It is possible to compare the results of several simulations.

This allows, for example, to measure the impact of a vulnerability that we introduce between two simulations.

```
$ python3 utils/comp_res.py <PATH_TO_SIM_RES1> <PATH_TO_SIM_RES2>
```

For example:

```
$ python3 utils/comp_res.py use_cases/teleworking/sim_res/res_sim_with_patch.txt use_cases/teleworking/sim_res/res_sim_without_patch.txt
```

A file "comp_res.txt" is created in the directory where the command is executed and contains the difference between the two simulations.



### Generation of curves


It is possible to generate a graphical curve to visualize the evolution of the probabilities of the attack graph nodes.

```
$ python3 utils/build_graph.py <PATH_TO_CONFIG_FILE> <SIM_FILE>
```

For example:

```
$ python3 utils/build_graph.py use_cases/teleworking/config.json sim_res.txt
```


The result file of the simulations <SIM_FILE> must be present in the "sim_res/" directory of the project. It can be the result of simulations obtained with the command "utils/calc_prob_from_sim.py" or the calculation of the difference between two simulations obtained with the command "utils/comp_res.py".



## Use cases <a name="usecases"></a>


### Remote working


The remote work use case presents an example of a system where a user moves regularly between the company network and his home network. This highlights the benefits of modeling the dynamic behavior of computer systems when assessing the risk of a cyber attack.


### Complex system

A script allows to generate variables listing all the components of the system such as VoIP phones, computer stations and remote working users:

```
$ python3 var_generator.py [CONFIG FILE PATH] [PROJECT CONFIG FILE PATH]
```

The first parameter indicates the path to the configuration file that allows to indicate the number of desired machines and the percentage of remote users. A default file is present in the dynamic-attack-graph-dag/use_cases/real_it_network directory.

The second parameter indicates the path to the project configuration file.

After running the script, 3 files are generated:
* *pc.p*: Indicates the evolution of remote working users
* *var_ipc.P*: Indicates the IP phones present in the system
* *var_pc.P*: Indicates the computers present in the system

These files should be placed in the dynamic-attack-graph-dag/use_cases/real_it_network/timed_input directory


### benchmark


The script benchmark_nb_host.sh allows to launch a benchmark of the solution by progressively increasing the number of users in the remote work use case.

The script benchmark_nb_vuln.sh allows to launch a benchmark of the solution by progressively increasing the number of vulnerabilities present on the web server in the remote work use case.

It is possible to perform a benchmark with and without the optimizations by changing the parameter in the project configuration file.


## References <a name="references"></a>

1. Attack Graph-based Solution for Vulnerabilities Impact Assessment in Dynamic Environment, CIOT'22. Antoine Boudermine, Rida Khatoun, Jean-Henri Choyer. 2022 (https://ieeexplore.ieee.org/document/9766588)
2. Dynamic Logic-Based Attack Graph for Risk Assessment in Complex Computer Systems, Computer Networks. Antoine Boudermine, Rida Khatoun, Jean-Henri Choyer. 2023 (https://authors.elsevier.com/a/1gqlu4xsUs7n2R)
3. Risk Assessment in Complex Systems: A Survey. Antoine Boudermine, Rida Khatoun, Jean-Henri Choyer. 2023  [Not yet published]
