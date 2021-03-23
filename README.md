# [libcsuit](https://github.com/yuichitk/libcsuit/)
**libcsuit** is a C library for encoding and decoding [IETF SUIT manifests](https://tools.ietf.org/html/draft-ietf-suit-manifest).
The manifest contains meta-data about the firmware image. The manifest is protected against modification and provides information 
about the software/firmware author.

For more information on how the IETF SUIT manifest is used to protect firmware updates of IoT devices, please look at the
 [IETF SUIT architecture](https://datatracker.ietf.org/doc/html/draft-ietf-suit-architecture) document and the 
 [IETF SUIT](https://datatracker.ietf.org/wg/suit/about/) working group.

## Overview

This implementation uses
 - the [QCBOR] (https://github.com/laurencelundblade/QCBOR) library for encoding and decoding CBOR structures,
 - the [t_cose] (https://github.com/laurencelundblade/t_cose) library for cryptographic processing of COSE structures, 
 - OpenSSL or Mbed TLS (based on the PSA Crypto API) for cryptographic algorithms.
 
This implementation offers a subset of the functionality defined in [draft-ietf-suit-manifest-11](https://tools.ietf.org/html/draft-ietf-suit-manifest-11).
 
Example programs are offered for testing. 

## Getting started

This library uses two build systems, namely cmake and classical makefiles. 

### Using Makefiles 

Installing [QCBOR](https://github.com/laurencelundblade/QCBOR).
```bash
git clone https://github.com/laurencelundblade/QCBOR.git
cd QCBOR
make install
```

Make and run sample codes you need.

- suit_manifest_parser
```bash
make -f Makefile.parser test
```

- suit_manifest_encoder
```bash
make -f Makefile.encode test
# generates ./testfiles/suit_manifest_expX.cbor
```

To install libcsuit.a use the following command:
```
make install
```

To nstall libcsuit.so use the following command: 
```
make install_so
```

### Using CMake 

The cmake file allows building code for OpenSSL and for Mbed TLS based on a parameter passed to cmake. 
If you decide to use OpenSSL then you need to download and install it before building this library.
The OpenSSL library and the include files need to be included in the search path. 

First, create a directory for the entire project. Inside this directory put the code of qcbor, t_cose, 
mbedtls (if used), and libcsuit. 

Here are the commands:

```
git clone https://github.com/hannestschofenig/t_cose.git
git clone https://github.com/hannestschofenig/QCBOR.git
git clone https://github.com/ARMmbed/mbedtls.git
git clone https://github.com/hannestschofenig/libcsuit.git
cd libcsuit
git checkout psa
```

Next, build the code using cmake

```
mkdir build
cd build
cmake -DMBEDTLS=1 ..
make 
```

If you want to build the code for OpenSSL then omit the '-DMBEDTLS=1' parameter from the cmake invocation. 



## SUIT Protocol Message Examples
The following description Markdown and CBOR files are compliant with [draft-ietf-suit-manifest-11](https://tools.ietf.org/html/draft-ietf-suit-manifest-11).
- Example 0
  - [suit_manifest_exp0.md](https://github.com/yuichitk/libcsuit/blob/master/testfiles/suit_manifest_exp0.md)
  - [suit_manifest_exp0.cbor](https://github.com/yuichitk/libcsuit/blob/master/testfiles/suit_manifest_exp0.cbor)
- Example 1
  - [suit_manifest_exp1.md](https://github.com/yuichitk/libcsuit/blob/master/testfiles/suit_manifest_exp1.md)
  - [suit_manifest_exp1.cbor](https://github.com/yuichitk/libcsuit/blob/master/testfiles/suit_manifest_exp1.cbor)
- Example 2
  - [suit_manifest_exp2.md](https://github.com/yuichitk/libcsuit/blob/master/testfiles/suit_manifest_exp2.md)
  - [suit_manifest_exp2.cbor](https://github.com/yuichitk/libcsuit/blob/master/testfiles/suit_manifest_exp2.cbor)
- Example 3
  - [suit_manifest_exp3.md](https://github.com/yuichitk/libcsuit/blob/master/testfiles/suit_manifest_exp3.md)
  - [suit_manifest_exp3.cbor](https://github.com/yuichitk/libcsuit/blob/master/testfiles/suit_manifest_exp3.cbor)
- Example 4
  - [suit_manifest_exp4.md](https://github.com/yuichitk/libcsuit/blob/master/testfiles/suit_manifest_exp4.md)
  - [suit_manifest_exp4.cbor](https://github.com/yuichitk/libcsuit/blob/master/testfiles/suit_manifest_exp4.cbor)
- Example 5
  - [suit_manifest_exp5.md](https://github.com/yuichitk/libcsuit/blob/master/testfiles/suit_manifest_exp5.md)
  - [suit_manifest_exp5.cbor](https://github.com/yuichitk/libcsuit/blob/master/testfiles/suit_manifest_exp5.cbor)

## License and Copyright
BSD 2-Clause License

Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
