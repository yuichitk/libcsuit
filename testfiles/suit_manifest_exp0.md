<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    B.1.  Example 0: Secure Boot
    https://tools.ietf.org/html/draft-ietf-suit-manifest-11#appendix-B.1


## CBOR Diagnostic
    / SUIT_Envelope = /
    {
        / authentication-wrapper / 2 : bstr .cbor ({
            digest : bstr .cbor ([
                / algorithm-id / 2 / "sha256" /,
                / digest-bytes / h'5c097ef64bf3bb9b494e71e1f2418eef8d466cc902f639a855ec9af3e9eddb99'
            ])
            signatures : [
                bstr .cbor (18([
                    / protected / bstr .cbor ({
                        / alg / 1 : -7 / "ES256" /,
                    }),
                    / unprotected / {
                    },
                    / payload / bstr .cbor ([
                        / algorithm-id / 2 / "sha256" /,
                        / digest-bytes / h'5c097ef64bf3bb9b494e71e1f2418eef8d466cc902f639a855ec9af3e9eddb99'
                    ]),
                    / signature / h'60f5c3d03a3aa759bfef2ef0f5f97a93b1f5e741f7463f4385af88513a5c2957bea2d6c4cfddd03392a267aab0fc0fd515560ed58e33fad26ac32a024c5a7143'
                ]))
            ]
        }),
        / manifest / 3 : bstr .cbor ({
            / manifest-version / 1 : 1,
            / manifest-sequence-number / 2 : 0,
            / common / 3 : bstr .cbor ({
                / components / 2 : [
                    [h'00']
                ],
                / common-sequence / 4 : bstr .cbor ([
                    / directive-override-parameters / 20,
                    {
                        / vendor-id / 1 : h'fa6b4a53d5ad5fdfbe9de663e4d41ffe' / fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe /,
                        / class-id / 2 : h'1492af1425695e48bf429b2d51f2ab45' / 1492af14-2569-5e48-bf42-9b2d51f2ab45 /,
                        / image-digest / 3 : bstr .cbor ([
                            / algorithm-id / 2 / "sha256" /,
                            / digest-bytes / h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
                        ]),
                        / image-size / 14 : 34768,
                    },
                    / condition-vendor-identifier / 1, 15,
                    / condition-class-identifier / 2, 15
                ]),
            }),
            / validate / 10 : bstr .cbor ([
                / condition-image-match / 3, 15
            ]),
            / run / 12 : bstr .cbor ([
                / directive-run / 23, 2
            ]),
        }),
    }


## CBOR binary
    A2                                      # map(2)
       02                                   # unsigned(2)
       58 98                                # bytes(152)
          825824820258205C097EF64BF3BB9B494E71E1F2418EEF8D466CC902F639A855EC9AF3E9EDDB99586FD28443A10126A05824820258205C097EF64BF3BB9B494E71E1F2418EEF8D466CC902F639A855EC9AF3E9EDDB99584060F5C3D03A3AA759BFEF2EF0F5F97A93B1F5E741F7463F4385AF88513A5C2957BEA2D6C4CFDDD03392A267AAB0FC0FD515560ED58E33FAD26AC32A024C5A7143
       03                                   # unsigned(3)
       58 71                                # bytes(113)
          A50101020003585FA202818141000458568614A40150FA6B4A53D5AD5FDFBE9DE663E4D41FFE02501492AF1425695E48BF429B2D51F2AB450358248202582000112233445566778899AABBCCDDEEFF0123456789ABCDEFFEDCBA98765432100E1987D0010F020F0A4382030F0C43821702


## CBOR binary (extracted)
    A2                                      # map(2)
       02                                   # unsigned(2) / authentication-wrapper : /
       58 98                                # bytes(152)
          # SUIT_Authentication #
          82                                # array(2)
             58 24                          # bytes(36)
                # SUIT_Digest #
                82                          # array(2)
                   02                       # unsigned(2) / algorithm-id : "sha256" /
                   58 20                    # bytes(32)   / digest-bytes /
                      5C097EF64BF3BB9B494E71E1F2418EEF8D466CC902F639A855EC9AF3E9EDDB99
             58 6F                          # bytes(111)
                # SUIT_Authentication_Block #
                D2                          # tag(18) / COSE_Sign1 /
                   84                       # array(4)
                      43                    # bytes(3)
                         # protected #
                         A1                 # map(1)
                            01              # unsigned(1) / alg : /
                            26              # negative(6) / -7 /
                      A0                    # map(0)
                      58 24                 # bytes(36)
                         # payload = SUIT_Digest #
                         82                 # array(2)
                            02              # unsigned(2) / algorithm-id : "sha256" /
                            58 20           # bytes(32)   / digest-bytes /
                               5C097EF64BF3BB9B494E71E1F2418EEF8D466CC902F639A855EC9AF3E9EDDB99
                      58 40                 # bytes(64)   / signature /
                         60F5C3D03A3AA759BFEF2EF0F5F97A93B1F5E741F7463F4385AF88513A5C2957BEA2D6C4CFDDD03392A267AAB0FC0FD515560ED58E33FAD26AC32A024C5A7143
       03                                   # unsigned(3) / manifest : /
       58 71                                # bytes(113)
          # SUIT_Manifest #
          A5                                # map(5)
             01                             # unsigned(1) / manifest-version : /
             01                             # unsigned(1)
             02                             # unsigned(2) / manifest-sequence-number : /
             00                             # unsigned(0)
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
                         14                 # unsigned(20) / directive-override-parameters : /
                         A4                 # map(4)
                            01              # unsigned(1) / vendor-id : /
                            50              # bytes(16)
                               FA6B4A53D5AD5FDFBE9DE663E4D41FFE
                            02              # unsigned(2) / class-id : /
                            50              # bytes(16)
                               1492AF1425695E48BF429B2D51F2AB45
                            03              # unsigned(3) / image-digest : /
                            58 24           # bytes(36)
                               # SUIT_Digest #
                               82           # array(2)
                                  02        # unsigned(2) / algorithm-id : "sha256" /
                                  58 20     # bytes(32)   / digest-bytes /
                                     00112233445566778899AABBCCDDEEFF0123456789ABCDEFFEDCBA9876543210
                            0E              # unsigned(14) / image-size : /
                            19 87D0         # unsigned(34768)
                         01                 # unsigned(1)  / condition-vendor-identifier : /
                         0F                 # unsigned(15)
                         02                 # unsigned(2)  / condition-class-identifier : /
                         0F                 # unsigned(15)
             0A                             # unsigned(10) / validate : /
             43                             # bytes(3)
                # SUIT_Command_Sequence #
                82                          # array(2)
                   03                       # unsigned(3)  / condition-image-match : /
                   0F                       # unsigned(15)
             0C                             # unsigned(12) / run : /
             43                             # bytes(3)
                # SUIT_Command_Sequence #
                82                          # array(2)
                   17                       # unsigned(23) / directive-run : /
                   02                       # unsigned(2)


## Command
    echo -en "\xA2\x02\x58\x98\x82\x58\x24\x82\x02\x58\x20\x5C\x09\x7E\xF6\x4B\xF3\xBB\x9B\x49\x4E\x71\xE1\xF2\x41\x8E\xEF\x8D\x46\x6C\xC9\x02\xF6\x39\xA8\x55\xEC\x9A\xF3\xE9\xED\xDB\x99\x58\x6F\xD2\x84\x43\xA1\x01\x26\xA0\x58\x24\x82\x02\x58\x20\x5C\x09\x7E\xF6\x4B\xF3\xBB\x9B\x49\x4E\x71\xE1\xF2\x41\x8E\xEF\x8D\x46\x6C\xC9\x02\xF6\x39\xA8\x55\xEC\x9A\xF3\xE9\xED\xDB\x99\x58\x40\x60\xF5\xC3\xD0\x3A\x3A\xA7\x59\xBF\xEF\x2E\xF0\xF5\xF9\x7A\x93\xB1\xF5\xE7\x41\xF7\x46\x3F\x43\x85\xAF\x88\x51\x3A\x5C\x29\x57\xBE\xA2\xD6\xC4\xCF\xDD\xD0\x33\x92\xA2\x67\xAA\xB0\xFC\x0F\xD5\x15\x56\x0E\xD5\x8E\x33\xFA\xD2\x6A\xC3\x2A\x02\x4C\x5A\x71\x43\x03\x58\x71\xA5\x01\x01\x02\x00\x03\x58\x5F\xA2\x02\x81\x81\x41\x00\x04\x58\x56\x86\x14\xA4\x01\x50\xFA\x6B\x4A\x53\xD5\xAD\x5F\xDF\xBE\x9D\xE6\x63\xE4\xD4\x1F\xFE\x02\x50\x14\x92\xAF\x14\x25\x69\x5E\x48\xBF\x42\x9B\x2D\x51\xF2\xAB\x45\x03\x58\x24\x82\x02\x58\x20\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x0E\x19\x87\xD0\x01\x0F\x02\x0F\x0A\x43\x82\x03\x0F\x0C\x43\x82\x17\x02" > suit_manifest_exp0.cbor
