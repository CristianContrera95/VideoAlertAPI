## Correr en la maquina donde se ejecutara el docker

# download mysql
docker pull mysql

# Executar mysql with name and root password
docker run --name=mysql-local -e MYSQL_ROOT_PASSWORD=pidata20! -d mysql

# Get mysql ip address
docker inspect mysql-local | grep "IPAddress"  # Con esta ip y el puerto: 3306 te podes conectar

# Create database
docker exec -ti mysql-local bash

## Dentro del docker
mysql -u root -p

CREATE DATABASE MineSecurity2;

CREATE USER 'api_account'@'localhost' IDENTIFIED BY '123456';

GRANT ALL PRIVILEGES ON databaseName.* TO 'api_account'@'localhost';

FLUSH PRIVILEGES;

QUIT

exit


## Correr en la maquina donde se ejecutara la API

# install driver and connector
sudo apt-get install python-dev default-libmysqlclient-dev
sudo apt-get install python3-dev
pip install mysqlclient


# download driver:
# https://dev.mysql.com/downloads/connector/odbc/

gunzip mysql-connector-odbc-8.0.19-linux-glibc2.12-x86-64bit.tar.gz
tar xvf mysql-connector-odbc-8.0.19-linux-glibc2.12-x86-64bit.tar
cd mysql-connector-odbc-8.0.19-linux-glibc2.12-x86-64bit/
sudo cp bin/* /usr/local/bin
sudo cp lib/* /usr/local/lib
sudo myodbc-installer -a -d -n "MySQL ODBC 8.0 Driver" -t "Driver=/usr/local/lib/libmyodbc8w.so"
sudo myodbc-installer -a -d -n "MySQL ODBC 8.0" -t "Driver=/usr/local/lib/libmyodbc8a.so"
myodbc-installer -d -l