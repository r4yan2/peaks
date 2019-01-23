#!/bin/bash

set -e

__exists() {
    which $1 1>/dev/null 2>&1
}

get="fetch";
! __exists fetch && get="curl -OL";

starting_path=$PWD;
cpus=`cat /proc/cpuinfo | grep processor | wc -l`;

if [ ! -d lib/gmp ];
then

    echo 'Compiling GMP'

    if [ ! -d gmp-6.1.2 ];
    then

        if [ ! -f gmp-6.1.2.tar.bz2 ];
        then
            $get https://gmplib.org/download/gmp/gmp-6.1.2.tar.bz2
        fi

        sum=`openssl sha256 gmp-6.1.2.tar.bz2 | awk -F' ' '{print $2}'`

        if [[ $sum != "5275bb04f4863a13516b2f39392ac5e272f5e1bb8057b18aec1c9b79d73d8fb2" ]];
        then
            echo ''
            echo '=========================================='
            echo 'ERROR: could not verify gmp-6.1.2.tar.bz2;'
            echo 'Downloaded over untrusted channel (non-https)'
            echo '=========================================='
            exit;
        fi
        
        if [ ! -f gmp-6.1.2.patch ];
        then
            $get https://raw.githubusercontent.com/D-o-c/fastgcd/9605906557a397db0630d67dc7bbe5d60f2e2fc4/gmp-6.1.2.patch
        fi

        sum=`openssl sha256 gmp-6.1.2.patch | awk -F' ' '{print $2}'`

        if [[ $sum != "fe3b261f2d93ce2647f3bcb969b7a1c5e4db054a3b6eb02694f722bb2999c1b6" ]];
        then
            echo ''
            echo '=========================================='
            echo 'ERROR: could not verify gmp-6.1.2.patch;'
            echo 'Downloaded over untrusted channel (non-https)'
            echo '=========================================='
            exit;
        fi
        
        tar xf gmp-6.1.2.tar.bz2
    fi

    cd gmp-6.1.2
    patch -p 1 < ../gmp-6.1.2.patch
    if [ "$1" == "debug" ];
    then
        ./configure --prefix=$starting_path/lib/gmp --disable-shared # --enable-cxx CXXFLAGS="-g -O2 -march=native" --disable-shared
    elif [ "$1" == "release" ];
    then
        ./configure --prefix=$starting_path/lib/gmp --disable-static CFLAGS="-Ofast -march=native"
    elif [ "$1" == "docker" ];
    then
        ./configure --prefix=$starting_path/lib/gmp --disable-static CFLAGS="-Ofast"
    else
        echo "ERROR! Option not recognized, use debug or release to specify the purpose."
        exit;
    fi
    make -j$cpus
    if [ "$3" == "check" ];
    then
        make check -j$cpus
    fi
    make install
    
    cd $starting_path
    
    echo 'Removing GMP sources'

    rm -rf gmp*
    
fi


if [ ! -d lib/ntl ]
then

    echo 'Compiling NTL'

    if [ ! -d ntl-10.5.0 ];
    then

        if [ ! -f ntl-10.5.0.tar.gz ];
        then
            $get http://www.shoup.net/ntl/ntl-10.5.0.tar.gz
        fi

        sum=`openssl sha256 ntl-10.5.0.tar.gz | awk -F' ' '{print $2}'`

        if [[ $sum != "b90b36c9dd8954c9bc54410b1d57c00be956ae1db5a062945822bbd7a86ab4d2" ]];
        then
            echo ''
            echo '=========================================='
            echo 'ERROR: could not verify ntl-10.5.0.tar.gz;'
            echo 'Downloaded over untrusted channel (non-https)'
            echo '=========================================='
            exit;
        fi

        gunzip ntl-10.5.0.tar.gz
        tar xf ntl-10.5.0.tar
    fi

    cd ntl-10.5.0/src
    if [ "$1" == "debug" ]
    then
        ./configure NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on NTL_STD_CXX11=on "CXXFLAGS=-g -march=native" PREFIX=$starting_path/lib/ntl/ GMP_PREFIX=$starting_path/lib/gmp
    elif [ "$1" == "release" ]
    then
        ./configure NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on NTL_STD_CXX11=on "CXXFLAGS=-O3 -march=native -fopenmp -D_GLIBCXX_PARALLEL" PREFIX=$starting_path/lib/ntl/ GMP_PREFIX=$starting_path/lib/gmp
    elif [ "$1" == "docker" ]
    then
        ./configure NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on NTL_STD_CXX11=on "CXXFLAGS=-O3 -fopenmp -D_GLIBCXX_PARALLEL" PREFIX=$starting_path/lib/ntl/ GMP_PREFIX=$starting_path/lib/gmp
    else
        echo "ERROR! Option not recognized, use debug or release to specify the purpose."
        exit;
    fi
    make -j$cpus
    if [ "$3" == "check" ];
    then
        make check -j$cpus
    fi
    make install

    cd $starting_path

    echo 'Removing NTL sources'

    rm -rf ntl*
fi

if [ ! -d lib/cppcms ]
then

    echo 'Compiling CPPCMS'

    if [ ! -d cppcms-1.2.1 ];
    then

        if [ ! -f cppcms-1.2.1.tar.bz2 ]
        then
            $get https://kent.dl.sourceforge.net/project/cppcms/cppcms/1.2.1/cppcms-1.2.1.tar.bz2
        fi

        tar -xjf cppcms-1.2.1.tar.bz2
    fi

    cd cppcms-1.2.1
    mkdir build
    cd build
    if [ "$1" == "debug" ]
    then
        cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=$starting_path/lib/cppcms/ ..
    elif [ "$1" == "release" ]
    then
        cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$starting_path/lib/cppcms/ ..
    else
        echo "ERROR! Option not recognized, use debug or release to specify the purpose."
        exit;
    fi
    make -j$cpus
    if [ "$3" == "check" ]
    then
        make test -j$cpus
    fi
    make install

    cd $starting_path

    echo 'Removing CPPCMS sources'

    rm -rf cppcms*

fi

if [ -d OpenPGP ]
then

    echo 'Compiling OpenPGP'

    cd OpenPGP
    make -j$cpus gpg-compatible
    
    cd $starting_path
fi
