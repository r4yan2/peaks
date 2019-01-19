# Peaks Compilation and Usage
## Compile
### Dependencies

* build-essential (and cmake)
* Boost Libraries
	* System
	* Filesystem
	* Program Options
    * Regex
* cppcms
    * pcre development files
    * zlib development files
* mysqlcppconnector
* OpenPGP: switch to branch *pks_branch* and compile with ```make gpg-compatible```
* NTL and GMP: exec ```./compile_libraries.sh release```

**On Debian/Ubuntu you can install all dependencies with**

```
apt install build-essential m4 curl python cmake libpcre3-dev libicu-dev libgcrypt11-dev zlib1g-dev libbz2-dev libgmp-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev libboost-regex-dev libmysqlcppconn-dev

./compile_libraries.sh release full
```

### Database

Use schema.sql to init Mysql DB

### Peaks

```bash
mkdir build && cd build/ \
&& cmake -DCMAKE_BUILD_TYPE=Release .. \
&& make
```

The binary will output in the **/bin** subdirectory

## Usage

The main **peaks** executable accept the following commands:

* import - will import the pgp dump into the database
* build - proceed to create the ptree
* serve - serve the pgp infrastructure through the web interface
* recon - start reconing with other peers

passing the *-h* flag will give the list of accepted options

## Keyserver Setup

### Config

Make sure you have the peaks_config file in the same folder of the peaks binary or in these other two fixed places:

* /var/lib/peaks/peaks_config
* /etc/peaks/peaks_config

You should also update your *membership* file to peer with other users

### Initializing

For the keyserver setup use the following commands:

```
./peaks import -p path-to-keydump --fastimport
```
**NOTE:** Actually Peaks support importing only single-key dump.

**NOTE2:** At the current time we have surpassed the 5M keys, so to correctly swallow the load MySQL should be tuned accordingly by increasing:
* innodb_buffer_pool_size (make up to 50% of total RAM)
* innodb_log_file_size (make 1/4 of *buffer_pool_size*)
* innodb_log_buffer_size (possibly closer to *log_file_size*)

This will take a while, at the end the database will be populated with the dump 

```
./peaks build
```

Will init the ptree with the content of the database

```
./peaks serve -c config.js
```

Will start the web interface

```
./peaks recon
```

Will start reconing with the peers defined in your membership file
