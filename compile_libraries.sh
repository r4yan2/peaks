#!/bin/bash

set -e

__exists() {
    which $1 1>/dev/null 2>&1
}

get="fetch";
! __exists fetch && get="curl -OL";

PEAKS_PATH=$PWD;
NCPU=`cat /proc/cpuinfo | grep processor | wc -l`;
if [ -z "$TARGET" ];
then
    TARGET="Release"
fi

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
    PREFIX="$PEAKS_PATH"/lib/gmp
    if [ "$TARGET" == "Debug" ];
    then
        CFLAGS="-g3 -march=native"
    elif [ "$TARGET" == "Release" ];
    then
        CFLAGS="-Ofast -march=native"
    elif [ "$TARGET" == "Docker" ];
    then
        CFLAGS="-Os -march=x86-64 -mtune=generic"
    else
        echo "ERROR! Option not recognized, use debug or release to specify the purpose."
        exit;
    fi
    ./configure --prefix="$PREFIX" CFLAGS="$CFLAGS"
    make -j$NCPU
    if [ -n "$CHECK" ];
    then
        make check -j$NCPU
    fi
    make install
    
    cd "$PEAKS_PATH"
    
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
    PREFIX="$PEAKS_PATH"/lib/ntl
    if [ "$TARGET" == "Debug" ]
    then
        CXXFLAGS="-g3 -march=native"
        NATIVE="on"
        TUNE="auto"
    elif [ "$TARGET" == "Release" ]
    then
        CXXFLAGS="-O3 -fopenmp -D_GLIBCXX_PARALLEL"
        NATIVE="on"
        TUNE="auto"
    elif [ "$TARGET" == "Docker" ]
    then
        CXXFLAGS="-Os -march=x86-64 -fopenmp -D_GLIBCXX_PARALLEL"
        NATIVE="off"
        TUNE="x86"
    else
        echo "ERROR! Option not recognized, use debug or release to specify the purpose."
        exit;
    fi
    ./configure NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on NTL_STD_CXX11=on CXXFLAGS="$CXXFLAGS" NATIVE="$NATIVE" TUNE="$TUNE" PREFIX="$PREFIX" GMP_PREFIX="$PEAKS_PATH"/lib/gmp
    make -j$NCPU
    if [ -n "$CHECK" ];
    then
        make check -j$NCPU
    fi
    make install

    cd "$PEAKS_PATH"

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
    PREFIX="$PEAKS_PATH"/lib/cppcms
    cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" ..
    make -j$NCPU
    if [ -n "$CHECK" ]
    then
        make test -j$NCPU
    fi
    make install

    cd "$PEAKS_PATH"

    echo 'Removing CPPCMS sources'

    rm -rf cppcms*

fi

if [ ! -d lib/mariadbpp ]
then

    PREFIX="$PEAKS_PATH"/lib/mariadbpp

    echo 'Compiling Mariadb Cpp connector'

    if [ ! -d mariadbpp ];
    then
        git clone --recursive https://github.com/viaduck/mariadbpp
    fi

    cd mariadbpp
    mkdir build
    cd build
    cmake -DCMAKE_INSTALL_PREFIX="$PREFIX" ..
    make -j$NCPU
    make install

    cd "$PEAKS_PATH"

    echo 'Removing sources'

    rm -rf mariadbpp/
fi

if [ -d OpenPGP ]
then

    echo 'Compiling OpenPGP'

    cd OpenPGP
    make -j$NCPU gpg-compatible
    
    cd $PEAKS_PATH
fi
