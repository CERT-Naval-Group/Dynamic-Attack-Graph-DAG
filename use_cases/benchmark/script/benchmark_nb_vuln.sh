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


#!/bin/bash

install_dir=$(dirname $(dirname $(dirname $(dirname $(realpath $0)))))

for i in $(seq 3 10 1000)
do

	python3 genRemoteWorkingUseCase.py 3 $i

	cd $install_dir/utils/

	./dag.sh $install_dir/use_cases/benchmark/config.json > $install_dir/use_cases/benchmark/output_console.txt

	cd $install_dir/use_cases/benchmark/script/

	pred=$(cat ../input.P | wc -l)
	mulvalexectime=$(cat ../output_console.txt | grep "Execution time of MulVAL" | grep -o -E "[0-9]+(\.[0-9]+)?")
	graphsize=$(cat ../VERTICES.CSV | wc -l)
	loadinggraphtime=$(cat ../output_console.txt | grep "Execution time of the optimization :" | grep -o -E "[0-9]+(\.[0-9]+)?")
	dagexectime=$(cat ../output_console.txt | grep "Execution time of the simulation :" | grep -o -E "[0-9]+(\.[0-9]+)?")
	
	
	echo -e "$i\t$pred\t$graphsize\t$loadinggraphtime\t$mulvalexectime\t$dagexectime" | tr -s '\t'

	rm -f ../graphs/prob_by_time/*
	rm -f ../log/*
	rm -f ../output/*

done
