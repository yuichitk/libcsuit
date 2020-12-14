<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    B.2.  Example 1: Simultaneous Download and Installation of Payload
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
                82                          # array(2)
                   02                       # unsigned(2) / algorithm-id = "sha256" /
                   58 20                    # bytes(32) / digest-bytes /
                      987EEC85FA99FD31D332381B9810F90B05C2E0D4F284A6F4211207ED00FFF750
             58 6F                          # bytes(111)
                # SUIT_Authentication_Block #
                D2                          # tag(18) / COSE_Sign1 /
                   84                       # array(4)
                      43                    # bytes(3)
                         # protected #
                         A1                 # map(1)
                            01              # unsigned(1) / alg : /
                            26              # negative(6) / -7 /
                      A0                    # map(0) / unprotected /
                      58 24                 # bytes(36)
                         # payload = SUIT_Digest #
                         82                 # array(2)
                            02              # unsigned(2) / algorithm-id = "sha256" /
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
                # SUIT_Common_Sequence #
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
                # SUIT_Common_Sequence #
                86                          # array(6)
                   13                       # unsigned(19) / directive-set-parameters : /
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
                # SUIT_Common_Sequence #
                82                          # array(2)
                   03                       # unsigned(3)  / condition-image-match : /
                   0F                       # unsigned(15)


## Command
    echo -en "\xA2\x02\x58\x98\x82\x58\x24\x82\x02\x58\x20\x98\x7E\xEC\x85\xFA\x99\xFD\x31\xD3\x32\x38\x1B\x98\x10\xF9\x0B\x05\xC2\xE0\xD4\xF2\x84\xA6\xF4\x21\x12\x07\xED\x00\xFF\xF7\x50\x58\x6F\xD2\x84\x43\xA1\x01\x26\xA0\x58\x24\x82\x02\x58\x20\x98\x7E\xEC\x85\xFA\x99\xFD\x31\xD3\x32\x38\x1B\x98\x10\xF9\x0B\x05\xC2\xE0\xD4\xF2\x84\xA6\xF4\x21\x12\x07\xED\x00\xFF\xF7\x50\x58\x40\x75\x01\x41\xD6\x5B\x4F\x20\xA8\x8D\xC7\x0C\x67\x85\xA6\x7E\x0F\x4F\x08\x5A\xEA\xD8\x3B\xA2\x28\x9D\x6E\x37\x27\x15\x08\xCC\x91\xE0\xA0\x59\x2F\x5C\x94\x0C\x22\x57\xC9\xC0\xB2\x64\x03\xC0\xBA\x44\x77\xF2\xCE\x37\xB6\x00\x89\xFE\x02\xCD\xE7\x91\x1D\x1C\x15\x03\x58\x94\xA5\x01\x01\x02\x01\x03\x58\x5F\xA2\x02\x81\x81\x41\x00\x04\x58\x56\x86\x14\xA4\x01\x50\xFA\x6B\x4A\x53\xD5\xAD\x5F\xDF\xBE\x9D\xE6\x63\xE4\xD4\x1F\xFE\x02\x50\x14\x92\xAF\x14\x25\x69\x5E\x48\xBF\x42\x9B\x2D\x51\xF2\xAB\x45\x03\x58\x24\x82\x02\x58\x20\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x0E\x19\x87\xD0\x01\x0F\x02\x0F\x09\x58\x25\x86\x13\xA1\x15\x78\x1B\x68\x74\x74\x70\x3A\x2F\x2F\x65\x78\x61\x6D\x70\x6C\x65\x2E\x63\x6F\x6D\x2F\x66\x69\x6C\x65\x2E\x62\x69\x6E\x15\x02\x03\x0F\x0A\x43\x82\x03\x0F" > suit_manifest_exp1.cbor
