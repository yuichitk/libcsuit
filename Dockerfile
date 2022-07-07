FROM ubuntu

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install build-essential git
RUN apt-get -y install libssl-dev

WORKDIR /home/root
RUN git clone --depth 1 https://github.com/laurencelundblade/QCBOR.git
WORKDIR ./QCBOR
RUN make install
RUN make install_so

WORKDIR /home/root
RUN git clone --depth 1 https://github.com/laurencelundblade/t_cose.git
WORKDIR ./t_cose
RUN make -f Makefile.ossl libt_cose.a install

WORKDIR /home/root
RUN ldconfig
COPY . ./libcsuit
WORKDIR ./libcsuit
RUN make -f Makefile.parser

CMD make -f Makefile.parser test
