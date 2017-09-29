FROM ubuntu:16.04

RUN apt-get -y update && apt-get install -y \
    autoconf \
    bison \
    flex \
    gcc \
    g++ \
    git \
    libprotobuf-dev \
    libtool \
    make \
    pkg-config \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth=1 https://github.com/google/nsjail.git

WORKDIR /nsjail

RUN make && mv /nsjail/nsjail /bin && rm -rf -- /nsjail
