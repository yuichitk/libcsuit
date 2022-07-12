# Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
FROM debian:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install curl git gcc gdb make

WORKDIR /root
RUN curl -O https://www.openssl.org/source/openssl-3.0.5.tar.gz
RUN tar xzf openssl-3.0.5.tar.gz
WORKDIR ./openssl-3.0.5
RUN ./config
RUN make -j4
RUN make install
ENV LD_LIBRARY_PATH /usr/local/lib64
RUN ldconfig

WORKDIR /root
RUN git clone https://github.com/laurencelundblade/QCBOR.git
WORKDIR ./QCBOR
RUN git checkout 11ea361d803589dcfa38767594236afbc8789f8b
RUN make install

WORKDIR /root
RUN git clone https://github.com/laurencelundblade/t_cose.git
WORKDIR ./t_cose
RUN git checkout d5ff4e282d8af34e5756627cf877ab399e7e51af
RUN make -f Makefile.ossl libt_cose.a install

WORKDIR /root
RUN ldconfig
COPY . ./libcsuit
RUN mv ./libcsuit/.gdbinit /root
WORKDIR ./libcsuit
RUN make -f Makefile.encode CC=gcc
RUN make -f Makefile.parser CC=gcc
RUN make -f Makefile.process CC=gcc

CMD make -f Makefile.encode test && make -f Makefile.parser test && make -f Makefile.process test
