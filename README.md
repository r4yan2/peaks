Intro
-----

Peaks is an OpenPGP keyserver aiming to be fast, reliable, documented and able to sync with SKS keyserver

Contents
-------

* Install
    * Snap
    * Docker
    * Compile
* Configuration
    * Database
    * Config and membership
* Usage
* Docker-compose


Install
-------

## Snap

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/peaks)

By far the easieast and comfy solution, just

```bash
sudo snap install peaks
```

## Docker

```bash
docker pull peaks:latest
```

**Note**: the docker container is suitable to be used as stand alone binary

## Compile

Be sure to download the full repo (including submodules)

```bash
git clone --recursive https://github.com/r4yan2/peaks.git
```

or if you have just downloaded the zip archive of this repository without the submodule or cloned without `--recursive`

```bash
cd peaks/
git submodule update --init --recursive
```

Peaks depends on:
* build-essential (and cmake)
* Boost Libraries
	* System
	* Filesystem
	* Program Options
    * Unit Test Framework
* cppcms
    * pcre development files
    * zlib development files
* mysqlcppconnector
* NTL
* GMP
* OpenPGP

**On Debian/Ubuntu you can install part of the dependencies with**

```bash
apt-get install -y build-essential m4 curl python git libcurl4-openssl-dev libpcre3-dev libicu-dev libgcrypt20-dev zlib1g-dev libbz2-dev libgmp-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev libboost-test-dev libmysqlcppconn-dev libssl-dev
```

### Cmake

First of all install cmake if you still don't have it
```bash
apt install cmake
```

NTL, GMP and OpenPGP can be compiled running

```bash
BUILD=Release PREFIX=/usr/local ./compile_libraries.sh
```

Then, to compile the keyserver:

```bash
mkdir build && cd build/
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_LIB_PREFIX=/usr/local -DCMAKE_INSTALL_PREFIX=/usr/local/bin ..
make
```

`-DCMAKE_LIB_PREFIX` and `-DCMAKE_INSTALL_PREFIX` can be customized to suit your needs

Configuration
-----

## Database

peaks require a mysql 5.6 or 5.7 installation to work.
Using the ![docker image](https://hub.docker.com/_/mysql/) is perhaps the easiest and most straghtforward way to configure a mysql server, more on this in the [relevant section](#Docker)

In order to specify the database parameters to peaks you need to tweak the peaks settings, more on this in the upcoming sections

## Config and membership

Peaks will look for a configuration file `peaks_config` in one of the following locations:

* the current location
* `/var/lib/peaks/peaks_config`
* `/etc/peaks/peaks_config`

To generate a default configuration file

```bash
peaks config > peaks_config
```

Most of the default parameters will do just fine for most cases.
In particular you need to change the **database configuration** according to your system setup, otherwise peaks will hang or complain or both.

Please take a look into the [dedicated section](#options) to know more about the config.

In the configuration file it will be required to set up the location of the *membership* file
For those new to the keyserver, a membership file holds the information of the peer which agreed to synchronize key material with you. More info in the [membership](#membership) section


Usage
-----

The main **peaks** executable accept the following commands:

* config - will output a default configuration for peaks
* import - will import the pgp dump into the database
* build - proceed to create the ptree
* serve - serve the pgp infrastructure through the web interface
* recon - start reconing with other peers
* unpack - divide and analyze the stored certificates in the actual key material
* analyze - analyze the key material to find known vulnerabilities (**WARNING**: this will increase your database size and you will have no benefits from using this command)

`peaks -h` will give the list of accepted commands and options

## Initialization

You will need to have a collection of `pgp` dump that peaks will import.

```bash
peaks import --init <path_to_DB_initialization_file> --path <path_to_dump> --threads <N>
```

* `init` will let peaks handle the initialization of the DB schema. A file has been prepared for this purpose under the `bin` subdirectory. In case restrictive database access is used probably peaks will not have the necessary permission to init the DB. The process can be completed manually before the first run by using the dedicated `schema.sql` in the `database` folder.
* `path` should point to the folder keeping the .pgp files
* `threads` is the number of threads to use to parse the key material

**Note**: to reduce the operation time and the I/O stress on the target machine peaks will **not** import certificate in the database, just their metadata, so you should not remove them after the import procedure

In case you would like to discard the imported certificate data just connect to a mysql shell and issue

```sql
use gpg_keyserver;
truncate gpg_keyserver;
```

## Build the prefix tree

After succesfully importing the certificate you need to generate the ptree to reconcile with other keyservers

```bash
peaks build
```

## Start up the server process

To be able to query peaks from the web interface (and to allow other keyserver to fetch key-material from you) run

```bash
peaks serve
```



## Reconcile

To keep-up with other keyservers you need to start the daemon(s) provided with
peaks:

* reconciliation daemon
* unpacker daemon
* server
* (optional) if you are a researcher you might also be intrested to
  the analyzer, otherwise just pretend that such command does not exists

To start reconciling please setup the config file and the **membership** file accordingly. Then, just run

```bash
peaks recon
```

To run the daemon for the unpacking of key material (needed to allow humans to search keys from the web interface). This process will run in batch to avoid using too much resources, it will take a while to complete

```bash
peaks unpack
```

## Configuration options

Now will follow a list of the configuration options that could be modified from the main configuration file

### Generic settings


|Name|Default Value|Brief Explanation|Should be changed?|
|----|-----------------|-------------|------------------|
|mbar|      5|Parameter for the linear interpolation|                NO|
|bq  |       2|Regulate the fanout of the prefix-tree| NO               |
|pthree_thresh_mult|10| multiplicative constant| NO|
|P_SKS_STRING|5305128895516023225051275203|finite field used by SKS|NO|
|reconciliation_timeout|45|timeout for the reconciliation protocol|NO|
|version|1.1.6 |version sent to sks, needed for compatiblity|NO|
|recon_port|11372|Port of which expose the recon service|YES|
|http_port | 11373|Port on which expose the web server|YES|
|pks_bind_ip | 127.0.0.1|ip address on which bind the server|YES|
|filters | yminsky.dedup,yminsky.merge|filters to merge certificates|NO|
|name | peaks_recon|name of the server|YES|
|gossip_interval | 60 | interval between gossip attemps|YES|
|max_read_len_shift | 24 |max_read_len will be set according to this value| NO|
|max_recover_size | 15000 | maximum keys to be recovered in a single session| NO|
|default_timeout | 300 | default communication timout | YES|
|max_request_queue_len | 60000 | maximum length of the server request | NO|
|request_chunk_size | 100| maximum number of keys to be request whitin a single hashquery request|
|max_outstanding_recon_req | 100 ||
|sks_bitstring | 0     |compatibility mode|NO|
|async_timeout_sec | 1|network timeout - second|NO|
|async_timeout_usec | 0 |network timeout - millisecond|NO|
|unpacker_limit | 10000|Upper limit to the number of certificates unpacked in a single run|YES|
|analyzer_limit | 10000|Upper limit to the number of certificates analyzed in a single run|YES|

### Membership file

This file will host hostname and port of the keyserver that agree to reconcile with you.
Empty lines and lines commented via `#` are ignored
Note that the agreement with another keyserver operator is necessary: if your keyserver does not appear in the membership file of the other server it will refuse the connection.

```Example
yourserver.example.net         11370   # Your full name <emailaddress for admin purposes> 
keyserver.gingerbear.net       11370   # John P. Clizbe <John@Gingerbear.net>          
sks.keyservers.net             11370   # John P. Clizbe <John@Gingerbear.net>          
keyserver.rainydayz.org        11370   # Andy Ruddock <andy.ruddock@rainydayz.org>     
keyserver.computer42.org       11370   # H.-Dirk Schmitt <dirk@computer42.org>         

```

### Database settings

This settings needs to be changed according to your setup

|Name|Brief Explanation|
|----|-----------------|
|db_host |   database host   |
|db_user | database user    |
|db_database | database name|
|db_password| database user password|

### File and folders settings     

This settings might be changed according to your needs

|Name|Default Value|
|----|-----------------|
|membership_config | /etc/peaks/membership|
|default_dump_path | /tmp/pgp_dump/ |
|tmp_folder | /tmp/peaks_tmp |
|error_folder | /tmp/peaks_errors |

### Running tests

Tests can be compiled passing the appropriate parameter to cmake

`cmake -DTEST=ON`

test will be generated under bin/peaks-test

## Guidelines for commit

Short non tedius guidelines for commit titles, do whatever you want with the
message but try to explain why the commit was needed at least.

* [FIX] fixing stuff
* [CHG] changin stuff
* [IMP] new implementation
* [DEL] deleting stuff
