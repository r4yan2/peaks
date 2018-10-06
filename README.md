# Peaks
## Compile
### Dependencies

* Boost Libraries
	* System
	* Filesystem
	* Program Options
* cppcms
* mysqlcppconnector
* OpenPGP: switch to branch *pks_branch* and compile with ```make gpg-compatible```
* NTL and GMP: exec ```./compile_libraries.sh release```

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
