# Peaks_Code

Usare schema.sql per generare il database

Libreria OpenPGP: usare branch *pks_branch* e compilare con ```make gpg-compatible```

Librerie NTL e GMP: lanciare ```./compile_libraries.sh release```

Applicativi C++: compilare con
```bash
mkdir build && cd build/ \
&& cmake -DCMAKE_BUILD_TYPE=Release .. \
&& make -j4
```
L'eseguibile verrà creato nella sottocartella *bin*.

Recon Daemon: compilare con il classico *make*
