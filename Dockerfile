FROM ubuntu:16.04

RUN apt-get -y update && apt-get install -y \
    autoconf \
    bison \
    check \
    flex \
    gcc \
    git \
    libtool \
    make \
    pkg-config \
    protobuf-c-compiler \
    re2c \
&& rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/google/nsjail.git

WORKDIR /nsjail

RUN make && mv /nsjail/nsjail /bin && rm -rf -- /nsjail
