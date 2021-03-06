# [libcsuit](https://github.com/yuichitk/libcsuit/)
**libcsuit** is a C library for decoding [IETF SUIT Manifest](https://tools.ietf.org/html/draft-ietf-suit-manifest).

## Overview
 - Implemented C-native data representation.
 - Using [QCBOR](https://github.com/laurencelundblade/QCBOR) for decoding CBOR binary data.
 - This implementation is compliant with [draft-ietf-suit-manifest-11](https://tools.ietf.org/html/draft-ietf-suit-manifest-11).
 - There are a sample codes for interoperability testing.
   - Decoding a SUIT Manifest binary file.

## Getting started
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

## Install libcsuit.a
```
make install
```

## Install libcsuit.so
```
make install_so
```

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
