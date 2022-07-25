FROM debian:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get -y install curl git gcc gdb make cmake python3 python3-jinja2 libcunit1-dev

RUN git clone https://github.com/hannestschofenig/mbedtls.git /root/mbedtls
WORKDIR /root/mbedtls
RUN git checkout hpke
RUN make generated_files
RUN mkdir -p /root/mbedtls/build
WORKDIR /root/mbedtls/build
RUN cmake ..
RUN cmake --build .
RUN make install

RUN git clone https://github.com/laurencelundblade/QCBOR.git /root/QCBOR
WORKDIR /root/QCBOR
RUN make install

RUN git clone https://github.com/hannestschofenig/t_cose.git /root/t_cose
WORKDIR /root/t_cose
RUN git checkout latest_t_cose
RUN make -f Makefile.psa libt_cose.a install

RUN ldconfig
RUN git clone https://github.com/yuichitk/libcsuit.git /root/libcsuit
WORKDIR /root/libcsuit
RUN git checkout firmware-encryption

CMD make -f Makefile.cnrtypt MBEDTLS=1 test
