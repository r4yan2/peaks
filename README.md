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
* OpenPGP: switch to branch *pks_branch* and compile with ```make gpg-compatible```
* NTL and GMP: exec ```./compile_libraries.sh release```

**On Debian/Ubuntu you can install all dependencies with**

```
apt install build-essential m4 curl python cmake libpcre3-dev libicu-dev libgcrypt11-dev zlib1g-dev libbz2-dev libgmp-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev libmysqlcppconn-dev

./compile_libraries.sh release full
```

### Database

Use schema.sql to init Mysql DB

### Peaks

```bash
mkdir build && cd build/ \
&& cmake -DCMAKE_BUILD_TYPE=Release .. \
&& make -j$(nproc-1)
```

The binary will output in the **/bin** subdirectory

## Usage

The main **peaks** executable accept the following commands:

* import - will import the pgp dump into the database
* build - proceed to create the ptree
* serve - serve the pgp infrastructure through the web interface
* recon - start reconing with other peers

For the basic (and only) keyserver setup use the following commands:

```
./peaks import -p path-to-keydump
```

Will init the database with the keydump

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
