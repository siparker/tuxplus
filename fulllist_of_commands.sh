basic install and apt update

#get the full latest package from the download page
wget https://www.percona.com/downloads/Percona-Server-5.7/Percona-Server-5.7.22-22/binary/debian/bionic/x86_64/Percona-Server-5.7.22-22-rf62d93c-bionic-x86_64-bundle.tar

# untar it
tar xvf Percona-Server-5.7.22-22-rf62d93c-bionic-x86_64-bundle.tar

# install everything using dpkg
dpkg -i *.deb

