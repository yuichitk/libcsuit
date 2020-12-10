<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    https://tools.ietf.org/html/draft-ietf-suit-manifest-11#appendix-B.2


## CBOR Diagnostic
    / SUIT_Envelope = /
    {
        / authentication-wrapper / 2:bstr .cbor ({
            digest: bstr .cbor ([
                / algorithm-id / 2 / "sha256" /,
                / digest-bytes / h'987eec85fa99fd31d332381b9810f90b05c2e0d4f284a6f4211207ed00fff750'
            ])
            signatures: [
                bstr .cbor (18([
                    / protected / bstr .cbor ({
                        / alg / 1:-7 / "ES256" /,
                    }),
                    / unprotected / {
                    },
                    / payload / bstr .cbor ([
                        / algorithm-id / 2 / "sha256" /,
                        / digest-bytes / h'987eec85fa99fd31d332381b9810f90b05c2e0d4f284a6f4211207ed00fff750'
                    ]),
                    / signature / h'750141d65b4f20a88dc70c6785a67e0f4f085aead83ba2289d6e37271508cc91e0a0592f5c940c2257c9c0b26403c0ba4477f2ce37b60089fe02cde7911d1c15'
                ]))
            ]
        }),
        / manifest / 3:bstr .cbor ({
            / manifest-version / 1:1,
            / manifest-sequence-number / 2:1,
            / common / 3:bstr .cbor ({
                / components / 2:[
                    [h'00']
                ],
                / common-sequence / 4:bstr .cbor ([
                    / directive-override-parameters / 20,
                    {
                        / vendor-id / 1:h'fa6b4a53d5ad5fdfbe9de663e4d41ffe' / fa6b4a53-d5ad-5fdf-
    be9d-e663e4d41ffe /,
                        / class-id / 2:h'1492af1425695e48bf429b2d51f2ab45' / 1492af14-2569-5e48-bf42-9b2d51f2ab45 /,
                        / image-digest / 3:bstr .cbor ([
                            / algorithm-id / 2 / "sha256" /,
                            / digest-bytes / h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
                        ]),
                        / image-size / 14:34768,
                    },
                    / condition-vendor-identifier / 1,15,
                    / condition-class-identifier / 2,15
                ]),
            }),
            / install / 9:bstr .cbor ([
                / directive-set-parameters / 19,
                {
                    / uri / 21:'http://example.com/file.bin',
                },
                / directive-fetch / 21,2,
                / condition-image-match / 3,15
            ]),
            / validate / 10:bstr .cbor ([
                / condition-image-match / 3,15
            ]),
        }),
    }


## CBOR binary
    A2                                      # map(2)
       02                                   # unsigned(2)
       58 98                                # bytes(152)
          82582482025820987EEC85FA99FD31D332381B9810F90B05C2E0D4F284A6F4211207ED00FFF750586FD28443A10126A0582482025820987EEC85FA99FD31D332381B9810F90B05C2E0D4F284A6F4211207ED00FFF7505840750141D65B4F20A88DC70C6785A67E0F4F085AEAD83BA2289D6E37271508CC91E0A0592F5C940C2257C9C0B26403C0BA4477F2CE37B60089FE02CDE7911D1C15
       03                                   # unsigned(3)
       58 94                                # bytes(148)
          A50101020103585FA202818141000458568614A40150FA6B4A53D5AD5FDFBE9DE663E4D41FFE02501492AF1425695E48BF429B2D51F2AB450358248202582000112233445566778899AABBCCDDEEFF0123456789ABCDEFFEDCBA98765432100E1987D0010F020F0958258613A115781B687474703A2F2F6578616D706C652E636F6D2F66696C652E62696E1502030F0A4382030F


## CBOR binary (extracted)
    A2                                      # map(2)
       02                                   # unsigned(2) / suit-authentication-wrapper : /
       58 98                                # bytes(152)
          # SUIT_Authentication #
          82                                # array(2)
             58 24                          # bytes(36)
                # SUIT_Digest #
                82                          # array(2) / SUIT_Digest /
                   02                       # unsigned(2) / algorithm-id = "sha-256" /
                   58 20                    # bytes(32) / digest-bytes /
                      987EEC85FA99FD31D332381B9810F90B05C2E0D4F284A6F4211207ED00FFF750
             58 6F                          # bytes(111)
                # SUIT_Authentication_Block #
                D2                          # tag(18) / COSE_Sign1 /
                   84                       # array(4)
                      43                    # bytes(3)
                         # protected #
                         A1                 # map(1)
                            01              # unsigned(1) / alg /
                            26              # negative(6) / -7 /
                      A0                    # map(0) / unprotected /
                      58 24                 # bytes(36)
                         # payload #
                         82                 # array(2)
                            02              # unsigned(2) / algorithm-id = "sha-256" /
                            58 20           # bytes(32)   / digest-bytes /
                               987EEC85FA99FD31D332381B9810F90B05C2E0D4F284A6F4211207ED00FFF750
                      58 40                 # bytes(64)   / signature /
                         750141D65B4F20A88DC70C6785A67E0F4F085AEAD83BA2289D6E37271508CC91E0A0592F5C940C2257C9C0B26403C0BA4477F2CE37B60089FE02CDE7911D1C15
       03                                   # unsigned(3) / manifest : /
       58 94                                # bytes(148)
          # SUIT_Manifest #
          A5                                # map(5)
             01                             # unsigned(1) / manifest-version : /
             01                             # unsigned(1) / 1 /
             02                             # unsigned(2) / manifest-sequence-number : /
             01                             # unsigned(1) / 1 /
             03                             # unsigned(3) / common : /
             58 5F                          # bytes(95)
                # SUIT_Common #
                A2                          # map(2)
                   02                       # unsigned(2) / components : /
                   81                       # array(1)    / [[h'00']]
                      81                    # array(1)
                         41                 # bytes(1)
                            00              # "\x00"
                   04                       # unsigned(4) / common-sequence : /
                   58 56                    # bytes(86)
                      # SUIT_Common_Sequence #
                      86                    # array(6)
                         14                 # unsigned(20) / directive-override-parameters /
                         A4                 # map(4)
                            01              # unsigned(1)  / vendor-id : /
                            50              # bytes(16)
                               FA6B4A53D5AD5FDFBE9DE663E4D41FFE
                            02              # unsigned(2)  / class-id : /
                            50              # bytes(16)
                               1492AF1425695E48BF429B2D51F2AB45
                            03              # unsigned(3)  / image-digest : /
                            58 24           # bytes(36)
                               # SUIT_Digest #
                               82           # array(2)
                                  02        # unsigned(2)  / suit-digest-algorithm-ids : algorithm-id-sha256 /
                                  58 20     # bytes(32)    / suit-digest-bytes : /
                                     00112233445566778899AABBCCDDEEFF0123456789ABCDEFFEDCBA9876543210
                            0E              # unsigned(14)    / image-size : /
                            19 87D0         # unsigned(34768)
                         01                 # unsigned(1)  / condition-vendor-identifier : 15 /
                         0F                 # unsigned(15)
                         02                 # unsigned(2)  / condition-class-identifier : 15 /
                         0F                 # unsigned(15)
             09                             # unsigned(9)  / install : /
             58 25                          # bytes(37)
                # SUIT_Digest #
                86                          # array(6)
                   13                       # unsigned(19)
                   A1                       # map(1)
                      15                    # unsigned(21) / uri : /
                      78 1B                 # text(27) / "http://example.com/file.bin" /
                         687474703A2F2F6578616D706C652E636F6D2F66696C652E62696E
                   15                       # unsigned(21) / directive-fetch : 2 /
                   02                       # unsigned(2)
                   03                       # unsigned(3)  / condition-image-match : 15 /
                   0F                       # unsigned(15)
             0A                             # unsigned(10) / validate : /
             43                             # bytes(3)
                # SUIT_Command_Sequence #
                82                          # array(2)     / condition-image-match : [3, 15]/
                   03                       # unsigned(3)
                   0F                       # unsigned(15)


## Command
    echo -en "\xa2\x02\x58\x98\x82\x58\x24\x82\x02\x58\x20\x98\x7e\xec\x85\xfa\x99\xfd\x31\xd3\x32\x38\x1b\x98\x10\xf9\x0b\x05\xc2\xe0\xd4\xf2\x84\xa6\xf4\x21\x12\x07\xed\x00\xff\xf7\x50\x58\x6f\xd2\x84\x43\xa1\x01\x26\xa0\x58\x24\x82\x02\x58\x20\x98\x7e\xec\x85\xfa\x99\xfd\x31\xd3\x32\x38\x1b\x98\x10\xf9\x0b\x05\xc2\xe0\xd4\xf2\x84\xa6\xf4\x21\x12\x07\xed\x00\xff\xf7\x50\x58\x40\x75\x01\x41\xd6\x5b\x4f\x20\xa8\x8d\xc7\x0c\x67\x85\xa6\x7e\x0f\x4f\x08\x5a\xea\xd8\x3b\xa2\x28\x9d\x6e\x37\x27\x15\x08\xcc\x91\xe0\xa0\x59\x2f\x5c\x94\x0c\x22\x57\xc9\xc0\xb2\x64\x03\xc0\xba\x44\x77\xf2\xce\x37\xb6\x00\x89\xfe\x02\xcd\xe7\x91\x1d\x1c\x15\x03\x58\x94\xa5\x01\x01\x02\x01\x03\x58\x5f\xa2\x02\x81\x81\x41\x00\x04\x58\x56\x86\x14\xa4\x01\x50\xfa\x6b\x4a\x53\xd5\xad\x5f\xdf\xbe\x9d\xe6\x63\xe4\xd4\x1f\xfe\x02\x50\x14\x92\xaf\x14\x25\x69\x5e\x48\xbf\x42\x9b\x2d\x51\xf2\xab\x45\x03\x58\x24\x82\x02\x58\x20\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10\x0e\x19\x87\xd0\x01\x0f\x02\x0f\x09\x58\x25\x86\x13\xa1\x15\x78\x1b\x68\x74\x74\x70\x3a\x2f\x2f\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d\x2f\x66\x69\x6c\x65\x2e\x62\x69\x6e\x15\x02\x03\x0f\x0a\x43\x82\x03\x0f" > suit_manifest_exp1.cbor
