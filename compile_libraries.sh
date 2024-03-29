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
    NCPU=${nproc}
fi
if [ -z "$BUILD" ]
then
    BUILD="Docker"
fi
if [ -z "$GMP" ]
then
    GMP="ON"
fi
if [ -z "$CLEAN" ]
then
    if [ "$BUILD" == "Release" ]
    then
        CLEAN=1
    else
        CLEAN=0
    fi
fi


PEAKS_PATH=$PWD
LIB_PATH="$PREFIX"/lib
INCL_PATH="$PREFIX"/include

function compile_gmp () {
    if [ ! -f $LIB_PATH/libgmp.a ];
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
            CFLAGS="-g3 -O0"
        elif [ "$BUILD" == "Release" ];
        then
            CFLAGS="-Ofast"
        elif [ "$BUILD" == "Docker" ];
        then
            CFLAGS="-O3"
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
        
        if [ "$CLEAN" == "1" ]
        then
            echo 'Removing GMP sources'
            rm -rf gmp*
        fi
        
    fi
}

function compile_ntl () {
    if [ ! -f $LIB_PATH/libntl.a ]
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
            CXXFLAGS="-g3 -O0"
            NATIVE="off"
            TUNE="auto"
        elif [ "$BUILD" == "Release" ]
        then
            CXXFLAGS="-O3 -fopenmp -D_GLIBCXX_PARALLEL"
            NATIVE="on"
            TUNE="auto"
        elif [ "$BUILD" == "Docker" ]
        then
            CXXFLAGS="-O3 -fopenmp -D_GLIBCXX_PARALLEL"
            NATIVE="off"
            TUNE="auto"
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
    
        if [ "$CLEAN" == "1" ]
        then
            echo 'Removing NTL sources'
            rm -rf ntl*
        fi
    fi
}

function compile_cppcms () {
    if [[ ! -f $LIB_PATH/libcppcms.a || ! -f $LIB_PATH/libbooster.a ]]
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
    
        if [ "$CLEAN" == "1" ]
        then
            echo 'Removing CPPCMS sources'
            rm -rf cppcms*
        fi
    
    fi
}

function compile_boost () {
    if [ ! -f $LIB_PATH/libboost_filesystem.a ]
    then
    
        echo 'Compiling required boost lib'
    
        $get https://boostorg.jfrog.io/artifactory/main/release/1.76.0/source/boost_1_76_0.tar.bz2
        tar -xf boost_1_76_0.tar.bz2
        cd boost_1_76_0/
        ./bootstrap.sh --prefix="$PREFIX" --with-libraries=system,filesystem,program_options,test
        ./b2 link=static install
    
        cd "$PEAKS_PATH"
    
        if [ "$CLEAN" == "1" ]
        then
            echo 'Removing sources'
            rm -r boost_1_76_0/
            rm boost_1_76_0.tar.bz2
        fi
    fi
}

function compile_openpgp () {
    echo 'Compiling OpenPGP'
    
    if [ ! -f OpenPGP/CMakeLists.txt ]
    then
        git clone -b peaks https://github.com/r4yan2/OpenPGP
    fi
    cd OpenPGP
    mkdir build
    cd build
    if [ ! "$BUILD" == "Debug" ]
    then
        BUILD="Release"
    fi
    if [ "$GMP" == "ON" ]; then
        cmake -DCMAKE_BUILD_TYPE="$BUILD" -DCMAKE_INSTALL_PREFIX="$PREFIX" -DGMP_INCLUDES="$INCL_PATH" -DGPG_COMPATIBLE=ON -DBUILD_TESTS=OFF -DBUILD_CLI=OFF ..
    else
        cmake -DCMAKE_BUILD_TYPE="$BUILD" -DCMAKE_INSTALL_PREFIX="$PREFIX" -DGPG_COMPATIBLE=ON -DBUILD_TESTS=OFF -DBUILD_CLI=OFF ..
    fi
    make -j$NCPU install
    cd "$PEAKS_PATH"
    if [ "$CLEAN" == "1" ]
    then
        echo 'Removing sources'
        rm -r OpenPGP/
    fi
}

if [ "$GMP" == "ON" ]; then
    compile_gmp
fi
compile_ntl
compile_cppcms
compile_openpgp
