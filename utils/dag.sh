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

install_dir=$(dirname $(dirname $(realpath $0)))
export MULVALROOT="$install_dir/mulval/tools/mulval"
export PATH=$PATH:$MULVALROOT/bin:$MULVALROOT/utils:$install_dir/mulval/tools/XSB/bin

graph=0
while test $# -gt 0
do
    case "$1" in
        -g) graph=1
            ;;
	*) conf_path=$1
	    ;;
    esac
    shift
done


python3 $install_dir/utils/build_timed_graph.py $conf_path
$install_dir/core/bin/Release/dag.exe $conf_path

if (( $graph == 1 ))
then
	python3 $install_dir/utils/build_graph.py $conf_path res.txt
fi
