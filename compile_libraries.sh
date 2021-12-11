#!/bin/bash

set -e

__exists() {
    which $1 1>/dev/null 2>&1
}

get="fetch"
! __exists fetch && get="curl -OL"

if [ -z "$PREFIX" ]
then
    PREFIX=$PWD
fi
if [ -z "$NCPU" ]
then
    NCPU=1
fi
if [ -z "$BUILD" ]
then
    BUILD="Release"
fi

PEAKS_PATH=$PWD
LIB_PATH="$PREFIX"/lib
INCL_PATH="$PREFIX"/include

function compile_gmp () {
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
                $get https://raw.githubusercontent.com/r4yan2/fastgcd/9605906557a397db0630d67dc7bbe5d60f2e2fc4/gmp-6.1.2.patch
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
            pushd gmp-6.1.2
            patch -p 1 < ../gmp-6.1.2.patch
            popd
        fi
    
        cd gmp-6.1.2
        if [ "$BUILD" == "Debug" ];
        then
            CFLAGS="-g3 -march=native"
        elif [ "$BUILD" == "Release" ];
        then
            CFLAGS="-Ofast -march=native"
        elif [ "$BUILD" == "Docker" ];
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
        
        if [ ! "$BUILD" == "Debug" ]
        then
            echo 'Removing GMP sources'
            rm -rf gmp*
        fi
        
    fi
}

function compile_ntl () {
    if [ ! -d lib/ntl ]
    then
    
        echo 'Compiling NTL'
    
        if [ ! -d ntl-10.5.0 ];
        then
    
            if [ ! -f ntl-10.5.0.tar.gz ];
            then
                $get https://libntl.org/ntl-10.5.0.tar.gz
            fi
    
            sum=`openssl sha256 ntl-10.5.0.tar.gz | awk -F' ' '{print $2}'`
    
            if [[ $sum != "b90b36c9dd8954c9bc54410b1d57c00be956ae1db5a062945822bbd7a86ab4d2" ]];
            then
                echo ''
                echo '=========================================='
                echo 'ERROR: could not verify ntl-10.5.0.tar.gz;'
                echo '=========================================='
                exit;
            fi
    
            gunzip ntl-10.5.0.tar.gz
            tar xf ntl-10.5.0.tar
        fi
    
        cd ntl-10.5.0/src
        if [ "$BUILD" == "Debug" ]
        then
            CXXFLAGS="-g3 -march=native"
            NATIVE="on"
            TUNE="auto"
        elif [ "$BUILD" == "Release" ]
        then
            CXXFLAGS="-O3 -fopenmp -D_GLIBCXX_PARALLEL"
            NATIVE="on"
            TUNE="auto"
        elif [ "$BUILD" == "Docker" ]
        then
            CXXFLAGS="-Os -march=x86-64 -fopenmp -D_GLIBCXX_PARALLEL"
            NATIVE="off"
            TUNE="x86"
        else
            echo "ERROR! Option not recognized, use debug or release to specify the purpose."
            exit;
        fi
        ./configure NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on NTL_STD_CXX11=on CXXFLAGS="$CXXFLAGS" NATIVE="$NATIVE" TUNE="$TUNE" PREFIX="$PREFIX" GMP_PREFIX="$PREFIX"
        make -j$NCPU
        if [ -n "$CHECK" ];
        then
            make check -j$NCPU
        fi
        make install
    
        cd "$PEAKS_PATH"
    
        if [ ! "$BUILD" == "Debug" ]
        then
            echo 'Removing NTL sources'
            rm -rf ntl*
        fi
    fi
}

function compile_cppcms () {
    if [ ! -d lib/cppcms ]
    then
    
        echo 'Compiling CPPCMS'
    
        if [ ! -d cppcms-2.0.0.beta2 ];
        then
    
            if [ ! -f cppcms-2.0.0.beta2.tar.bz2 ]
            then
                $get https://netix.dl.sourceforge.net/project/cppcms/cppcms/2.0.0-beta2/cppcms-2.0.0.beta2.tar.bz2
            fi
    
            tar -xjf cppcms-2.0.0.beta2.tar.bz2
        fi
    
        cd cppcms-2.0.0.beta2
        mkdir build
        cd build
        cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" ..
        make -j$NCPU
        if [ -n "$CHECK" ]
        then
            make test -j$NCPU
        fi
        make install
    
        cd "$PEAKS_PATH"
    
        if [ ! "$BUILD" == "Debug" ]
        then
            echo 'Removing CPPCMS sources'
            rm -rf cppcms*
        fi
    
    fi
}

function compile_boost () {
    if [ ! -d lib/boost ]
    then
    
        echo 'Compiling required boost lib'
    
        $get https://boostorg.jfrog.io/artifactory/main/release/1.76.0/source/boost_1_76_0.tar.bz2
        tar -xf boost_1_76_0.tar.bz2
        cd boost_1_76_0/
        ./bootstrap.sh --prefix="$PREFIX" --with-libraries=system,filesystem,program_options,test
        ./b2 link=static install
    
        cd "$PEAKS_PATH"
    
        if [ ! "$BUILD" == "Debug" ]
        then
            echo 'Removing sources'
            rm -r boost_1_76_0/
            rm boost_1_76_0.tar.bz2
        fi
    fi
}

function compile_docker () {
    if [ ! -d lib/nghttp2 ] && [ "$BUILD" == "Docker" ]
    then
        echo "Compiling nghttp2 static lib"
        git clone https://github.com/nghttp2/nghttp2
        cd nghttp2
        mkdir build
        cd build
        cmake -DENABLE_STATIC_LIB=ON -DCMAKE_INSTALL_PREFIX="$PREFIX" ..
        make -j$NCPU install
        cd "$PEAKS_PATH"
    fi
}

function compile_openpgp () {
    echo 'Compiling OpenPGP'
    
    cd OpenPGP
    mkdir build
    cd build
    cmake -DCMAKE_BUILD_TYPE="$BUILD" -DCMAKE_INSTALL_PREFIX="$PREFIX" -DGMP_INCLUDES="$INCL_PATH" -DGMP_LIBRARIES="${LIB_PATH}/libgmp.so" -DGPG_COMPATIBLE=ON ..
    make -j$NCPU install
    cd "$PEAKS_PATH"
    if [ ! "$BUILD" == "Debug" ]
    then
        echo 'Removing sources'
        rm -r OpenPGP/
    fi
}

compile_gmp
compile_ntl
compile_cppcms
compile_openpgp
