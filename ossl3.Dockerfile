# Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
FROM debian:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get -y install curl git gcc make libcunit1-dev

WORKDIR /root
RUN curl -O https://www.openssl.org/source/openssl-3.0.7.tar.gz
RUN tar xzf openssl-3.0.7.tar.gz
WORKDIR /root/openssl-3.0.7
RUN ./config
RUN make install_sw
ENV LD_LIBRARY_PATH /usr/local/lib64
RUN ldconfig

RUN git clone --depth 1 https://github.com/laurencelundblade/QCBOR.git /root/QCBOR
WORKDIR /root/QCBOR
RUN make libqcbor.a install

RUN git clone --depth 1 https://github.com/laurencelundblade/t_cose.git /root/t_cose
WORKDIR /root/t_cose
RUN make -f Makefile.ossl libt_cose.a install

RUN ldconfig
COPY . /root/libcsuit
WORKDIR /root/libcsuit
RUN make
RUN make -f Makefile.encode
RUN make -f Makefile.parser
RUN make -f Makefile.process

CMD make test && \
    make -f Makefile.encode test && \
    make -f Makefile.parser test && \
    make -f Makefile.process test
