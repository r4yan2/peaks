Intro
-----

Peaks is an OpenPGP keyserver aiming to be fast, reliable, documented and able to sync with SKS keyserver

Contents
-------

* [Get](#get)
    * [Docker](#docker)
    * [Snap](#snap)
    * [Compile](#compile)
* [Configure](#configuration)
    * [Docker Compose](#dockercompose)
    * [Manual Configuration](#manual)
      * [Database](#database)
      * [Configuration files](#config_membership)
    * [Config file](#peaks_config)
* [Use](#usage)

<a name="get"/>

# Get

The easier way to get peaks is to use one of the packaged versions or, if you prefer, to compile it yourself

<a name="docker"/>

## Docker

```bash
docker pull r4yan2/peaks:slim
```

<a name="snap"/>

## Snap

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/peaks)

```bash
sudo snap install peaks
```

<a name="compile"/>

## Compile

Download the full repository

```bash
git clone https://github.com/r4yan2/peaks
```

or download and extract the zip archive of repository
https://github.com/r4yan2/peaks/archive/refs/heads/master.zip

Peaks depends on the following libraries and tools:
* build-essential
* cmake
* [Boost Libraries](https://www.boost.org/)
  * System
  * Filesystem
  * Program Options
  * Unit Test Framework
* curl development files
* pcre development files
* zlib development files
* mysql cpp connector
* [Gnu Multiple precision arithmetic library](https://gmplib.org/)

**On Debian/Ubuntu you can install these dependencies with**

```bash
apt-get install -y build-essential cmake m4 curl python git libcurl4-openssl-dev libpcre3-dev libicu-dev libgcrypt20-dev zlib1g-dev libbz2-dev libgmp-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev libboost-test-dev libmysqlcppconn-dev libssl-dev
```

Some dependencies are not packaged and needs to be compiled, a bash script has been created to do it automatically


```bash
BUILD=Release PREFIX=$PWD/lib ./compile_libraries.sh
```
* `PREFIX` might be changed according to your needs, if you would like a system install set as prefix `/usr/local` (You might need to execute the script with `sudo`)

NTL, GMP and OpenPGP libraries will be ready.
We can now compile the keyserver:

```bash
mkdir build && cd build/
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_LIB_PREFIX=../$PWD/lib -DCMAKE_INSTALL_PREFIX=/usr/local/bin ..
make
```

* `-DCMAKE_LIB_PREFIX` needs to match `PREFIX`
* `-DCMAKE_INSTALL_PREFIX` is the output folder of the binary, if removed, the output will be the `bin` folder in the project root

<a name="config"/>

# Configure

<a name="dockercompose"/>

## Docker Compose

The easiest way to have an up and running peaks keyserver is to use a `docker-compose` file.
As multiple configuration options are available, it is provided an example configuration that will work on most systems with minimal modifications

```
version: '3.3'

services:
    db:
      image: mysql:5.7
      volumes:
         - ./peaks_db:/var/lib/mysql:rw
      environment:
         MYSQL_ROOT_PASSWORD: "mysupersuperpassword"
      command: --innodb_buffer_pool_size=1000M --innodb_log_file_size=250M --innodb_log_buffer_size=250M --innodb_support_xa=0 --innodb_flush_log_at_trx_commit=0 --innodb_doublewrite=0 --max-allowed-packet=250M
    peaks:
      depends_on:
         - db
      image: r4yan2/peaks:slim
      volumes:
        - ./config:/etc/peaks
        - ./filestore:/var/peaks
        - ./pgp_dump:/tmp/pgp_dump
      environment:
        MYSQL_HOST: "db"
        MYSQL_PORT: 3306
        MYSQL_USER: "root"
        MYSQL_PASSWORD: "mysupersuperpassword"
      ports:
         - 11370:11370
         - 11371:11371
      command:
        - sh
        - -c
        - /srv/peaks/init.sh && svscan /srv/peaks/service
```

**Volumes/Mount**
* `peaks_db` is where the database will store the persistent data
* `config` is the path to the config folder, if an empty folder is provided, the init script will create a default config and membership file for you
* `filestore` will hold new key material
* `pgp_dump` is the path to the current dump, please note that references to these files will be used to retrieve key material when needed, so you **shall not** delete the files after setup

**Environment**
* `MYSQL_HOST` `MYSQL_PORT` `MYSQL_USER` `MYSQL_PASSWORD` may be changed as needed (just make sure `MYSQL_ROOT_PASSWORD` and `MYSQL_PASSORD` match)

**Commands**
* mysql command line is just an example to improve performances over the default parameters, if you are short on RAM it is possible to use just `--innodb_support_xa=0 --innodb_flush_log_at_trx_commit=0 --innodb_doublewrite=0`. However, the queries will possibly we slower.


The image contains a `init.sh` file that will take care of initialization.
Just run `docker-compose up -d`, the script will:
* inizialize the config, if necessary
* import the key material present in `pgp_dump`
* build the prefix tree required for reconciliation
* start peaks deamons:
  * web server, peaks web interface will be available at http://server-ip:port/pks
  * unpacker server, a indexing service to query the database from the web interface
  * reconciliation keyserver

<a name="manual"/>

## Manual configuration

<a name="database"/>

### Database

peaks require a mysql 5.6 or 5.7 installation to work.
No particular operation needs to be done in mysql itself, peaks will automatically set up the database. Just ensure there is an user with [create database permissions](https://dev.mysql.com/doc/refman/5.7/en/grant.html)

<a name="config_membership"/>

### Config and membership

Peaks will look for a configuration file `peaks_config` in one of the following locations:

* the `peaks` binary location
* `/var/lib/peaks/peaks_config`
* `/etc/peaks/peaks_config`

To generate a default configuration file

```bash
peaks config > peaks_config
```

Most of the default parameters will do just fine for most cases.
The **database configuration** needs to be changed according to your system setup, otherwise peaks will hang or complain or both.

Please take a look into the [dedicated section](#peaks_config) to know more about the config.

In the configuration file it will be required to set up the location of the *membership* file
For those new to the keyservers, a membership file holds the information of the peer which agreed to synchronize key material with you. More info in the [membership](#membership) section

<a name="usage"/>

# Use

The main **peaks** executable accept the following commands:

* config - will output a default configuration for peaks
* import - will import the pgp dump into the database
* build - proceed to create the ptree
* serve - serve the pgp infrastructure through the web interface
* recon - start reconing with other peers
* unpack - divide and analyze the stored certificates in the actual key material
* analyze - analyze the key material to find known vulnerabilities (**WARNING**: CPU/Memory/Disk intensive, for key security analysis only)

`peaks -h` will give the list of accepted commands and options

## Initialization

You will need to have a collection of `pgp` dump that peaks will import.

```bash
peaks import --init <path_to_DB_initialization_file> --path <path_to_dump> --threads <N>
```

* `init` DB initialization file. A `schema.sql` might be found under the `bin` folder
* `path` folder keeping the .pgp files
* `threads` number of threads to use

**Note**: to reduce the operation time, database size and I/O stress on the target machine peaks will **not** import certificate in the database, just their metadata, so you should not remove them after the import procedure

### Build the prefix tree

After succesfully importing the certificate you need to generate the metadata to reconcile with other keyservers

```bash
peaks build
```

### Start up the server process

To be able to query peaks from the web interface (and to allow other keyserver to fetch key-material from you) run

```bash
peaks serve
```

At the beginning, no key will be searchable using the web interface. This because the key material needs to be indexed first.
A daemon will slowly unpack the certificates
**Note** if you don't want/need the web search you can skip this step, the key can be directly fetched using the keyID/fingerprint via command line tools

```bash
peks unpack
```

### Reconcile

To start reconciling please setup the config file and the **membership** file accordingly.
Then, just run

```bash
peaks recon
```


### Blocklist

Sometimes it may be necessary for server administrator to block certain key.
Just provide the list of key IDs to the `blocklist` command.

Note that the blocked keys will be completely wiped from the database and cannot be readded again

```bash
peaks blocklist ID1 ID2
```

<a name="peaks_config"/>

## Configuration options

Now will follow a list of the configuration options that could be modified from the main configuration file

### Internal settings

These settings change the way metadata are organized or the behavior of reconciliation.
It is better to leave them as default

|Name|Default Value|Brief Explanation|Should be changed?|
|----|-----------------|-------------|------------------|
|mbar|      5|Parameter for the linear interpolation|                NO|
|bq  |       2|Regulate the fanout of the prefix-tree| NO               |
|pthree_thresh_mult|10| multiplicative constant| NO|
|P_SKS_STRING|5305128895516023225051275203|finite field used by SKS|NO|
|reconciliation_timeout|45|timeout for the reconciliation protocol|NO|
|max_read_len_shift | 24 |max_read_len will be set according to this value| NO|
|max_recover_size | 15000 | maximum keys to be recovered in a single session| NO|
|max_request_queue_len | 60000 | maximum length of the server request | NO|
|request_chunk_size | 100| maximum number of keys to be request whitin a single hashquery request|with care|
|max_outstanding_recon_req | 100 ||
|async_timeout_sec | 1|network timeout - second|NO|
|async_timeout_usec | 0 |network timeout - millisecond|NO|


### Generic settings

These settings are generic and may be changed

|Name|Default Value|Brief Explanation|Should be changed?|
|----|-----------------|-------------|------------------|
|version|1.1.6 |version sent to sks, needed for compatiblity|NO|
|recon_port|11372|Port of which expose the recon service|YES|
|http_port | 11373|Port on which expose the web server|YES|
|pks_bind_ip | 127.0.0.1|ip address on which bind the server|YES|
|filters | yminsky.dedup,yminsky.merge|filters to merge certificates|NO|
|name | peaks_recon|name of the server|YES|
|gossip_interval | 60 | interval between gossip attemps|YES|
|max_unpacker_keysize | unset | upper size limit to the key to index (in bytes) | YES|
|unpacker_interval | 60 | interval in seconds between indexing runs | YES |
|unpacker_threads | 1 | number of threads used by the indexer | YES|
|analyzer_interval | 60 | interval in seconds between analyzer runs | YES |
|analyzer_threads | 1 | number of threads used by the analyzer | YES|
|analyzer_rsa_modulus | 0 | whether to run the RSA modulus scan| YES|
|unpacker_limit | 10000 | limit number of keys indexed at once | YES |
|analyzer_limit | 10000 | limit number of keys analyzed at once | YES |
|cgi_serve_stats | 0 | whether to expose the statistics via api | YES|

#### Database settings

This settings needs to be changed according to your setup

|Name|Default Value|Brief Explanation|
|----|-------------|-----------------|
|db_host ||   database host   |
|db_user || database user    |
|db_database || database name|
|db_password|| database user password|

#### File and folders settings     

This settings might be changed according to your needs

|Name|Default Value|
|----|-----------------|
|membership_config | /etc/peaks/membership|
|default_dump_path | /tmp/pgp_dump/ |
|tmp_folder | /tmp/peaks_tmp |
|error_folder | /tmp/peaks_errors |
|filestorage_format | /var/peaks/filestorage/peaks_filestorage_%d.pgp | filestorage format |
|filestorage_maxsize | 100 | single file max size |
|expire_interval | 15 | expire interval for cache (statistics api only) |

<a name="membership"/>

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
