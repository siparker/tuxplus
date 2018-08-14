#!/bin/bash



# First uninstall any unnecessary packages and ensure that aptitude is installed. 
apt update
apt -y install aptitude
#Nano is already installed with ubuntu 18.04
# aptitude -y install nano
# LSB Release is already Installed 
#aptitude -y install lsb-release
#service apache2 stop
#service sendmail stop
#service bind9 stop
#service nscd stop
#aptitude -y purge nscd bind9 sendmail apache2 apache2.2-common

## get local ip address
#LOCAL_IP=`./functions/get_ip.py`
#
#
#        echo -n "Enter Desired Hostname: eg srv1 "; read SET_HOSTNAME;
#        echo -n "Enter admin email address "; read SET_EMAIL;
#        echo -n "Enter Desired FQDN: eg srv1.yourdomain.com"; read SET_FQDNHOSTNAME;
#        echo -n "Enter MYSQL Root Password"; read SET_MYSQLPASS;
#        echo " "
#        echo "setting up variables in config file"
#
#        sed -i 's/HOSTNAME=srv1/HOSTNAME=$SET_HOSTNAME'/' ./options.conf
#        echo "Hostname Set To $SET_HOSTNAME successfully"
#        sed -i 's/HOSTNAME_FQDN=srv1.yourdomain.com/HOSTNAME_FQDN=$SET_FQDNHOSTNAME'/' ./options.conf
#        echo "FQDN Set To $SET_FQDNHOSTNAME successfully"
#        sed -i 's/ADMIN_EMAIL="admin@yourdomain.com"/ADMIN_EMAIL="$SET_EMAIL"'/' ./options.conf
#        echo "Admin Email Set To $SET_EMAIL successfully"
#        sed -i 's/MYSQL_ROOT_PASSWORD=abcd1234/MYSQL_ROOT_PASSWORD=$SET_MYSQLPASS'/' ./options.conf
#        echo "Admin Email Set To $SET_MYSQLPASS successfully"
#        sed -i 's/SERVER_IP="0.0.0.0"/SERVER_IP="$LOCAL_IP"'/' ./options.conf
#        echo "Local Ip Address $LOCAL_IP set successfully"
#
## choose webserver
#while true; do
#        echo -n "Do you want to install Nginx 1 or Apache 2 "; read NGINX_APACHE;
#
#        if [ "$NGINX_APACHE" != '1' -a "$NGINX_APACHE" != '2' ]; then
#                echo -e "\033[31minput error! Please only input '1' or '2'\033[0m"
#        elif [ "$NGINX_APACHE" == "2" ]; then
#                sed -i 's/^WEBSERVER=[0-9]*/WEBSERVER='${NGINX_APACHE}'/' ./options.conf
#                echo "Using Apache"
#                break
#        else
#                sed -i 's/^WEBSERVER=[0-9]*/WEBSERVER='${NGINX_APACHE}'/' ./options.conf
#                echo "using Nginx"
#                break
#        fi
#
#done
## Choose DB Type
#while true; do
#        echo -n "Do you want to install MySQL (1), MariaDB (2) or Percona (3) "; read SET_DB;
#
#        if [ "$SET_DB" != '1' -a "$$SET_DB" != '2' -a "$$SET_DB" != '2']; then
#                echo -e "\033[31minput error! Please only input '1', '2' or '3'\033[0m"
#        elif [ "$SET_DB" == "1" ]; then
#                sed -i 's/^DBSERVER=[0-9]*/DBSERVER='${SET_DB}'/' ./options.conf
#                echo "Using MYSQL"
#                break
#        elif [ "$SET_DB" == "2" ]; then
#                sed -i 's/^DBSERVER=[0-9]*/DBSERVER='${SET_DB}'/' ./options.conf
#                echo "Using MariaDB"
#                break
#        else
#                sed -i 's/^WEBSERVER=[0-9]*/WEBSERVER='${SET_DB}'/' ./options.conf
#                echo "Using Percona"
#                break
#        fi
#
#done

echo ""
echo "Configuring /etc/apt/sources.list."
sleep 5
./setup.sh apt

echo ""
echo "Installing updates & configuring SSHD / hostname."
sleep 5
./setup.sh basic

echo ""
echo "Installing LAMP or LNMP stack."
sleep 5
./setup.sh install

echo ""
echo "Optimizing AWStats, PHP, logrotate & webserver config."
sleep 5
./setup.sh optimize

## Uncomment to secure /tmp folder
#echo ""
#echo "Securing /tmp directory."
## Use tmpdd here if your server has under 256MB memory. Tmpdd will consume a 1GB disk space for /tmp
#./setup.sh tmpfs

echo ""
echo "Installation complete!"
echo "Root login disabled."
echo "Please add a normal user now using the \"adduser\" command."
