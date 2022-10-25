# Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
FROM debian:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get -y install curl git gcc make libcunit1-dev python3

RUN git clone -b v3.1.0 --depth 1 https://github.com/Mbed-TLS/mbedtls.git /root/mbedtls
WORKDIR /root/mbedtls
RUN make install

RUN git clone --depth 1 https://github.com/laurencelundblade/QCBOR.git /root/QCBOR
WORKDIR /root/QCBOR
RUN make libqcbor.a install

RUN git clone --depth 1 https://github.com/laurencelundblade/t_cose.git /root/t_cose
WORKDIR /root/t_cose
RUN make -f Makefile.psa libt_cose.a install

RUN ldconfig
COPY . /root/libcsuit
WORKDIR /root/libcsuit
RUN make MBEDTLS=1
RUN make -f Makefile.encode MBEDTLS=1
RUN make -f Makefile.parser MBEDTLS=1
RUN make -f Makefile.process MBEDTLS=1

CMD make test MBEDTLS=1 && \
    make -f Makefile.encode MBEDTLS=1 test && \
    make -f Makefile.parser MBEDTLS=1 test && \
    make -f Makefile.process MBEDTLS=1 test
