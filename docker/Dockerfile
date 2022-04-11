FROM ubuntu:18.04
MAINTAINER Andrea Grazioso <grazioandre@gmail.com>

RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections \
    && apt-get update \
    && apt-get install -y -q dialog apt-utils build-essential m4 curl python cmake git libcurl4-openssl-dev libpcre3-dev libicu-dev libgcrypt20-dev zlib1g-dev libbz2-dev libgmp-dev libssl-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev libboost-test-dev libmysqlcppconn-dev daemontools mysql-client \
    && rm /usr/lib/x86_64-linux-gnu/libgmp.a \
    && rm /usr/include/x86_64-linux-gnu/gmp.h \
    && git clone https://github.com/r4yan2/peaks \
    && cd peaks \
    && git clone -b peaks https://github.com/r4yan2/OpenPGP \
    && BUILD=Docker PREFIX=/usr ./compile_libraries.sh \
    && mkdir build && cd build/ \
    && cmake -DCMAKE_BUILD_TYPE=Docker -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=/bin -DCMAKE_LIB_PREFIX=/usr .. \
    && make \
    && cd / \
    && rm -rf peaks \
    && apt-get remove -y dialog apt-utils build-essential m4 curl python cmake git \
    && apt-get autoremove -y \
    && apt-get autoclean \
    && mkdir /var/peaks/

COPY data /srv/peaks

CMD ["svscan", "/srv/service"]
