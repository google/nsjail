FROM ubuntu

RUN apt-get -y update
RUN apt-get -y install autoconf bison check flex gcc git libtool make pkg-config protobuf-c-compiler re2c
RUN git clone https://github.com/google/nsjail.git
RUN cd /nsjail && make
RUN mv /nsjail/nsjail /bin && rm -rf -- /nsjail

