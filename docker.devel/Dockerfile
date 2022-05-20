FROM ubuntu:18.04
MAINTAINER Andrea Grazioso <grazioandre@gmail.com>

RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections \
    && apt-get update \
    && apt-get install -y -q dialog apt-utils build-essential m4 curl python cmake git libmysqlcppconn7v5 daemontools mysql-client libcurl4 libcurl4-openssl-dev libpcre3 libpcre3-dev libicu60 libicu-dev libgcrypt20 libgcrypt20-dev zlib1g zlib1g-dev libbz2-1.0 libbz2-dev libgmp10 libgmp-dev libssl1.1 libssl-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev libboost-test-dev libmysqlcppconn-dev \
    && apt-get install -y -q vim valgrind cgdb \
    && rm /usr/lib/x86_64-linux-gnu/libgmp.a \
    && rm /usr/include/x86_64-linux-gnu/gmp.h \
    && git clone https://github.com/r4yan2/peaks \
    && cd peaks \
    && git clone -b peaks https://github.com/r4yan2/OpenPGP \
    && BUILD=Docker PREFIX=/peaks/lib ./compile_libraries.sh \
    && mkdir build && cd build/ \
    && cmake -DCMAKE_BUILD_TYPE=Static -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=/bin -DCMAKE_LIB_PREFIX=/peaks/lib .. \
    && make -j2 \
    && cd / \
    && mkdir -p /var/peaks/filestorage

COPY data /srv/peaks

CMD ["svscan", "/srv/service"]
