# Peaks Compilation and Usage
## Compile
### Dependencies

* build-essential (and cmake)
* Boost Libraries
	* System
	* Filesystem
	* Program Options
* cppcms
    * pcre development files
    * zlib development files
* mysqlcppconnector

* NTL, GMP, OpenPGP

**On Debian/Ubuntu you can install all dependencies with**

```bash
apt install build-essential m4 curl python cmake libpcre3-dev libicu-dev libgcrypt11-dev zlib1g-dev libbz2-dev libgmp-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev libboost-regex-dev libmysqlcppconn-dev
```

NTL, GMP and OpenPGP can be installed running

```bash
./compile_libraries.sh release full
```

### Database Initialization

Use provided schema.sql to initialize MySQL

**WARNING to MariaDB users**

I've encountered a bug using MariaDB client connector, which I currently have not investigated, so it is HIGHLY advised to use MySQL as database backend

### Peaks Keyserver

To compile the keyserver:

```bash
mkdir build && cd build/ \
&& cmake -DCMAKE_BUILD_TYPE=Release .. \
&& make -j<insert_your_favourite_number_here>
```

The binary will output in the **/bin** subdirectory

## Usage

The main **peaks** executable accept the following commands:

* import - will import the pgp dump into the database
* build - proceed to create the ptree
* serve - serve the pgp infrastructure through the web interface
* recon - start reconing with other peers
* unpack - divide and analyze the stored certificates in the actual key material
* analyze - analyze the key material to find known vulnerabilities

passing the *-h* flag will give the list of accepted options

## Keyserver Setup

### Config File

Peaks use the following config files:

* peaks_config (main config)
* config.js (web server config)
* membership (needed to establish connection for recon)

Make sure you have the main config file in the same folder of the peaks binary or in these other two places:

* /var/lib/peaks/peaks_config
* /etc/peaks/peaks_config

From the main config is possible to specify the position of the other two. Please take a look into the dedicated section to know more about the config, in particular you need to change the database configuration before actually using peaks

### Database preparation

To have a smooth ride, it's avised to perform some optimization to the database. Since we actually have more than 5M certificates to import MySQL need to be prepared accordingly by tuning:

* innodb_buffer_pool_size (make up to 50% of total RAM)
* innodb_log_file_size (make 1/4 of *buffer_pool_size*)
* innodb_log_buffer_size (possibly closer to *log_file_size*)
* innodb_doublewrite = 0
* innodb_support_xa = 0
* innodb_flush_log_at_trx_commit = 0

Also is necessary to change the following config value to use the integrated web server

```sql
SET GLOBAL sql_mode=(SELECT REPLACE(@@sql_mode,'ONLY_FULL_GROUP_BY',''));
```

Optionally is also possible to disable MySQL logging to speed up bulk insert queries

```sql
SET global general_log = 0;

```

### Initializing

To initialize the database use the following commands:

```
./peaks import -p path-to-keydump --fastimport
```

**NOTE:** Actually Peaks support importing only single-key dump. Sorry.

This will take a while, at the end the database will be populated with the dump 

To generate the single-key dump from sks you can use the following command

```bash
sks dump 1 /destination/directory [name-prefix]
```

### Ptree building

After succesfully importing the certificate you need to generate the ptree to recon with other keyservers

```
./peaks build
```

## Usage

To keep-up with other keyservers you need to start the reconciliation daemon

```bash
./peaks recon
```

To be able to query peaks from the web interface (and to allow other keyserver to fetch key-material from you) run

```bash
./peaks serve
```

## Configuration options

Now will follow a list of the configuration options that could be modified from the main configuration file

### Generic settings

|Name|Default Value|Brief Explanation|Should be changed?|
|----|-----------------|-------------|------------------|
|mbar|      5|Parameter for the linear interpolation|                NO|
|bq  |       2|Regulate the fanout of the prefix-tree| NO               |
|max_ptree_nodes|      |1000|NO|
|pthree_thresh_mult|10|NO|
|P_SKS_STRING|5305128895516023225051275203|finite field used by SKS|NO|
|reconciliation_timeout|45|timeout for the reconciliation protocol|NO|
|peaks_version|1.1.6 |version sent to sks, needed for compatiblity|NO|
|peaks_recon_port|11372|Port of which expose the recon service|YES|
|peaks_http_port | 11373|Port on which expose the web server|YES|
|peaks_filters | yminsky.dedup,yminsky.merge|filters to merge certificates|NO|
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
|max_unpacker_limit | 10000|Upper limit to the number of certificates unpakced ad a time|YES|
|unpack_on_import | 0     |unpack keys upon importing|NO|

### Database settings

|Name|Brief Explanation|
|----|-----------------|
|db_host |   database host   |
|db_user | database user    |
|db_database | database name|
|db_password| database user password|

### File and folders settings     

|Name|Default Value|
|----|-----------------|
|membership_config | /etc/peaks/membership|
|cppcms_config | /etc/peaks/config.js |
|default_dump_path | /tmp/pgp_dump/ |
|dumpimport_tmp_folder | /tmp/dump_import/ |
|dumpimport_error_folder | /tmp/dumpimport_errors/ |
|analyzer_tmp_folder | /tmp/analyzer/ |
|unpacker_tmp_folder | /tmp/unpacker/|
|recon_tmp_folder | /tmp/recon/           |
|analyzer_error_folder | /tmp/analyzer_error|
|unpacker_error_folder | /tmp/unpacker_error|
|analyzer_gcd_folder | /tmp/gcd_tmp_folder/ |
