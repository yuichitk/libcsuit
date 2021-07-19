<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    B.4.  Example 3: A/B images
    https://tools.ietf.org/html/draft-ietf-suit-manifest-12#appendix-B.4


## CBOR Diagnostic
    / SUIT_Envelope = /
    {
        / authentication-wrapper / 2 : bstr .cbor ([
            / digest / bstr .cbor ([
                / algorithm-id / 2 / "sha256" /,
                / digest-bytes / h'ae0c1ea689c9800a843550f38796b6fdbd52a0c78be5d26011d8e784da43d47c'
            ])
            / signature / bstr .cbor (18([
                / protected / bstr .cbor ({
                    / alg / 1 : -7 / "ES256" /,
                }),
                / unprotected / {
                },
                / payload / F6 / nil /,
                / signature / h'1296c87d168bb857495e6551730f9d6d3a6d81ad6c908c72fbc52ddcb2e8011d20d217b3f1c028374eecbda5d2ca26d047270b397dcaa91a48a7c78cf376004e'
            ]))
        ]),
        / manifest / 3 : bstr .cbor ({
            / manifest-version / 1 : 1,
            / manifest-sequence-number / 2 : 3,
            / common / 3 : bstr .cbor ({
                / components / 2 : [
                     [h'00']
                ],
                / common-sequence / 4: bstr .cbor ([
                    / directive-override-parameters / 20,
                    {
                      / vendor-id / 1 : h'fa6b4a53d5ad5fdfbe9de663e4d41ffe' / fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe /,
                      / class-id / 2 : h'1492af1425695e48bf429b2d51f2ab45' / 1492af14-2569-5e48-bf42-9b2d51f2ab45 /,
                    },
                    / directive-try-each / 15,
                    [
                        bstr .cbor ([
                            / directive-override-parameters / 20,
                            {
                                / offset / 5 : 33792,
                            } ,
                            / condition-component-offset / 5, 5,
                            / directive-override-parameters / 20,
                            {
                                / image-digest / 3:bstr .cbor ([
                                    / algorithm-id / 2 / "sha256" /,
                                    / digest-bytes / h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
                                ]),
                                / image-size / 14 : 34768,
                            }
                        ]),
                        bstr .cbor ([
                            / directive-override-parameters / 20,
                            {
                                / offset / 5 : 541696,
                            },
                            / condition-component-offset / 5, 5,
                            / directive-override-parameters / 20,
                            {
                                / image-digest / 3 : bstr .cbor ([
                                    / algorithm-id / 2 / "sha256" /,
                                    / digest-bytes / h'0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff'
                                ]),
                                / image-size / 14 : 76834,
                            }
                        ])
                    ],
                    / condition-vendor-identifier / 1, 15,
                    / condition-class-identifier / 2, 15
                ]),
            }),
            / install / 9:bstr .cbor ([
                / directive-try-each / 15,
                [
                    bstr .cbor ([
                        / directive-set-parameters / 19,
                        {
                            / offset / 5 : 33792,
                        },
                        / condition-component-offset / 5, 5,
                        / directive-set-parameters / 19,
                        {
                            / uri / 21 : 'http://example.com/file1.bin',
                        }
                    ]),
                    bstr .cbor ([
                        / directive-set-parameters / 19,
                        {
                            / offset / 5:541696,
                        },
                        / condition-component-offset / 5, 5,
                        / directive-set-parameters / 19,
                        {
                            / uri / 21 : 'http://example.com/file2.bin',
                        }
                    ])
                ],
                / directive-fetch / 21, 2,
                / condition-image-match / 3, 15
            ]),
            / validate / 10 : bstr .cbor ([
                / condition-image-match / 3, 15
            ]),
        }),
    }


## CBOR binary
    A2                                      # map(2)
       02                                   # unsigned(2)
       58 73                                # bytes(115)
          82582482025820AE0C1EA689C9800A843550F38796B6FDBD52A0C78BE5D26011D8E784DA43D47C584AD28443A10126A0F658401296C87D168BB857495E6551730F9D6D3A6D81AD6C908C72FBC52DDCB2E8011D20D217B3F1C028374EECBDA5D2CA26D047270B397DCAA91A48A7C78CF376004E
       03                                   # unsigned(3)
       59 011B                              # bytes(283)
          A5010102030358AAA202818141000458A18814A20150FA6B4A53D5AD5FDFBE9DE663E4D41FFE02501492AF1425695E48BF429B2D51F2AB450F8258368614A105198400050514A20358248202582000112233445566778899AABBCCDDEEFF0123456789ABCDEFFEDCBA98765432100E1987D0583A8614A1051A00084400050514A2035824820258200123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF0E1A00012C22010F020F095861860F82582A8613A105198400050513A115781C687474703A2F2F6578616D706C652E636F6D2F66696C65312E62696E582C8613A1051A00084400050513A115781C687474703A2F2F6578616D706C652E636F6D2F66696C65322E62696E1502030F0A4382030F


## CBOR binary (extracted)
    A2                                              # map(2)
       02                                           # unsigned(2) / suit-authentication-wrapper : /
       58 73                                        # bytes(115)
          # SUIT_Authentication #
          82
             58 24                                  # bytes(36)
                # SUIT_Digest #
                82                                  # array(2)
                   02                               # unsigned(2) / algorithm-id : "sha256" /
                   58 20                            # bytes(32)   / digest-bytes /
                      AE0C1EA689C9800A843550F38796B6FDBD52A0C78BE5D26011D8E784DA43D47C
             58 4A                                  # bytes(74)
                D2                                  # tag(18) / COSE_Sign1 /
                   84                               # array(4)
                      43                            # bytes(3)
                         # protected #
                         A1                         # map(1)
                            01                      # unsigned(1) / alg /
                            26                      # negative(6) / -7 /
                      A0                            # map(0)
                      F6                            # primitive(22) / null /
                      58 40                         # bytes(64) / signature /
                         1296C87D168BB857495E6551730F9D6D3A6D81AD6C908C72FBC52DDCB2E8011D20D217B3F1C028374EECBDA5D2CA26D047270B397DCAA91A48A7C78CF376004E
       03                                           # unsigned(3) / manifest : /
       59 011B                                      # bytes(283)
          # SUIT_Manifest #
          A5                                        # map(5)
             01                                     # unsigned(1) / manifest-version : /
             01                                     # unsigned(1)
             02                                     # unsigned(2) / manifest-sequence-number : /
             03                                     # unsigned(3)
             03                                     # unsigned(3) / common : /
             58 AA                                  # bytes(170)
                # SUIT_Common #
                A2                                  # map(2)
                   02                               # unsigned(2) / components : /
                   81                               # array(1)    / [[h'00']]
                      81                            # array(1)
                         41                         # bytes(1)
                            00                      # "\x00"
                   04                               # unsigned(4) / common-sequence : /
                   58 A1                            # bytes(161)
                      # SUIT_Common_Sequence #
                      88                            # array(8)
                         14                         # unsigned(20) / directive-override-parameters : /
                         A2                         # map(2)
                            01                      # unsigned(1)  / vendor-id : /
                            50                      # bytes(16)
                               FA6B4A53D5AD5FDFBE9DE663E4D41FFE
                            02                      # unsigned(2)  / class-id : /
                            50                      # bytes(16)
                               1492AF1425695E48BF429B2D51F2AB45
                         0F                         # unsigned(15) / directive-try-each : /
                         82                         # array(2)
                            58 36                   # bytes(54)
                               # SUIT_Common_Sequence #
                               86                   # array(6)
                                  14                # unsigned(20) / directive-override-parameters : /
                                  A1                # map(1)
                                     05             # unsigned(5)  / offset : /
                                     19 8400        # unsigned(33792)
                                  05                # unsigned(5)  / condition-component-offset : /
                                  05                # unsigned(5)
                                  14                # unsigned(20) / directive-override-parameters : /
                                  A2                # map(2)
                                     03             # unsigned(3)  / image-digest : /
                                     58 24          # bytes(36)
                                        # SUIT_Digest #
                                        82          # array(2)
                                           02       # unsigned(2)  / algorithm-id : "sha256" /
                                           58 20    # bytes(32)    / digest-bytes /
                                              00112233445566778899AABBCCDDEEFF0123456789ABCDEFFEDCBA9876543210
                                     0E             # unsigned(14) / image-size : /
                                     19 87D0        # unsigned(34768)
                            58 3A                   # bytes(58)
                               # SUIT_Common_Sequence #
                               86                   # array(6)
                                  14                # unsigned(20) / directive-override-parameters : /
                                  A1                # map(1)
                                     05             # unsigned(5)  / offset : /
                                     1A 00084400    # unsigned(541696)
                                  05                # unsigned(5)  / condition-component-offset : /
                                  05                # unsigned(5)
                                  14                # unsigned(20) / directive-override-parameters : /
                                  A2                # map(2)
                                     03             # unsigned(3)  / image-digest : /
                                     58 24          # bytes(36)
                                        # SUIT_Digest #
                                        82          # array(2)
                                           02       # unsigned(2)  / algorithm-id : "sha256" /
                                           58 20    # bytes(32)    / digest-bytes /
                                              0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF
                                     0E             # unsigned(14) / image-size : /
                                     1A 00012C22    # unsigned(76834)
                         01                         # unsigned(1)  / condition-vendor-idnetifier : /
                         0F                         # unsigned(15)
                         02                         # unsigned(2)  / condition-class-identifier : /
                         0F                         # unsigned(15)
             09                                     # unsigned(9)  / install : /
             58 61                                  # bytes(97)
                # SUIT_Common_Sequence #
                86                                  # array(6)
                   0F                               # unsigned(15) / directive-try-each : /
                   82                               # array(2)
                      58 2A                         # bytes(42)
                         # SUIT_Common_Sequence #
                         86                         # array(6)
                            13                      # unsigned(19) / directive-set-parameters : /
                            A1                      # map(1)
                               05                   # unsigned(5)  / offset : /
                               19 8400              # unsigned(33792)
                            05                      # unsigned(5)  / condition-component-offset : /
                            05                      # unsigned(5)
                            13                      # unsigned(19) / directive-set-parameters : /
                            A1                      # map(1)
                               15                   # unsigned(21) / uri : /
                               78 1C                # text(28)     / "http://example.com/file1.bin" /
                                  687474703A2F2F6578616D706C652E636F6D2F66696C65312E62696E
                      58 2C                         # bytes(44)
                         # SUIT_Common_Sequence #
                         86                         # array(6)
                            13                      # unsigned(19) / directive-set-parameters : /
                            A1                      # map(1)
                               05                   # unsigned(5)  / offset : /
                               1A 00084400          # unsigned(541696)
                            05                      # unsigned(5)  / condition-component-offset : /
                            05                      # unsigned(5)
                            13                      # unsigned(19) / directive-set-parameters : /
                            A1                      # map(1)
                               15                   # unsigned(21) / uri : /
                               78 1C                # text(28)     / "http://example.com/file2.bin" /
                                  687474703A2F2F6578616D706C652E636F6D2F66696C65322E62696E
                   15                               # unsigned(21) / directive-fetch : /
                   02                               # unsigned(2)
                   03                               # unsigned(3)  / condition-image-match : /
                   0F                               # unsigned(15)
             0A                                     # unsigned(10) / validate : /
             43                                     # bytes(3)
                # SUIT_Common_Sequence #
                82                                  # array(2)
                   03                               # unsigned(3)  / condition-image-match : /
                   0F                               # unsigned(15)


## Command
    echo -en "\xA2\x02\x58\x73\x82\x58\x24\x82\x02\x58\x20\xAE\x0C\x1E\xA6\x89\xC9\x80\x0A\x84\x35\x50\xF3\x87\x96\xB6\xFD\xBD\x52\xA0\xC7\x8B\xE5\xD2\x60\x11\xD8\xE7\x84\xDA\x43\xD4\x7C\x58\x4A\xD2\x84\x43\xA1\x01\x26\xA0\xF6\x58\x40\x12\x96\xC8\x7D\x16\x8B\xB8\x57\x49\x5E\x65\x51\x73\x0F\x9D\x6D\x3A\x6D\x81\xAD\x6C\x90\x8C\x72\xFB\xC5\x2D\xDC\xB2\xE8\x01\x1D\x20\xD2\x17\xB3\xF1\xC0\x28\x37\x4E\xEC\xBD\xA5\xD2\xCA\x26\xD0\x47\x27\x0B\x39\x7D\xCA\xA9\x1A\x48\xA7\xC7\x8C\xF3\x76\x00\x4E\x03\x59\x01\x1B\xA5\x01\x01\x02\x03\x03\x58\xAA\xA2\x02\x81\x81\x41\x00\x04\x58\xA1\x88\x14\xA2\x01\x50\xFA\x6B\x4A\x53\xD5\xAD\x5F\xDF\xBE\x9D\xE6\x63\xE4\xD4\x1F\xFE\x02\x50\x14\x92\xAF\x14\x25\x69\x5E\x48\xBF\x42\x9B\x2D\x51\xF2\xAB\x45\x0F\x82\x58\x36\x86\x14\xA1\x05\x19\x84\x00\x05\x05\x14\xA2\x03\x58\x24\x82\x02\x58\x20\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x0E\x19\x87\xD0\x58\x3A\x86\x14\xA1\x05\x1A\x00\x08\x44\x00\x05\x05\x14\xA2\x03\x58\x24\x82\x02\x58\x20\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x0E\x1A\x00\x01\x2C\x22\x01\x0F\x02\x0F\x09\x58\x61\x86\x0F\x82\x58\x2A\x86\x13\xA1\x05\x19\x84\x00\x05\x05\x13\xA1\x15\x78\x1C\x68\x74\x74\x70\x3A\x2F\x2F\x65\x78\x61\x6D\x70\x6C\x65\x2E\x63\x6F\x6D\x2F\x66\x69\x6C\x65\x31\x2E\x62\x69\x6E\x58\x2C\x86\x13\xA1\x05\x1A\x00\x08\x44\x00\x05\x05\x13\xA1\x15\x78\x1C\x68\x74\x74\x70\x3A\x2F\x2F\x65\x78\x61\x6D\x70\x6C\x65\x2E\x63\x6F\x6D\x2F\x66\x69\x6C\x65\x32\x2E\x62\x69\x6E\x15\x02\x03\x0F\x0A\x43\x82\x03\x0F" > suit_manifest_exp3.cbor
