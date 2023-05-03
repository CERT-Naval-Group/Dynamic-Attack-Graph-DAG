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

export install_dir=$(dirname $(realpath $0))

exec_dir=$(pwd)
current_year=$(date | cut -d ' ' -f 4)

echo $http_proxy
sudo -E apt update
sudo -E apt -y install mysql-server lynx python3-lxml python3-pip default-jre graphviz texlive-font-utils libmysqlcppconn-dev build-essential g++ autotools-dev libicu-dev libbz2-dev libboost-date-time-dev
sudo -E pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org mysql-connector-python matplotlib scikit-learn

sudo mysql < utils/script.sql

cd "$install_dir/cve-database/nvd/scripts/"
./downloader.sh $current_year

cd "$install_dir/cve-database/mitre/scripts/"
./downloader.sh

cd "$install_dir/cve-database/scripts/"
python3 database_feeding.py


cd $install_dir/utils/

python3 cvss_to_attack_time.py

cd $install_dir/core/

make release

cd $install_dir/mulval/tools/XSB/build/
./configure
./makexsb

cd $install_dir/../

sudo cp -r dynamic-attack-graph-dag /opt/
sudo chown -R $USER /opt/dynamic-attack-graph-dag/
sudo chgrp -R $USER /opt/dynamic-attack-graph-dag/

sudo ln -s /opt/dynamic-attack-graph-dag/utils/dag.sh /bin/dagSIM
