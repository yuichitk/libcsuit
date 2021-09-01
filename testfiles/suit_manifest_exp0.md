<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    B.1.  Example 0: Secure Boot
    https://tools.ietf.org/html/draft-ietf-suit-manifest-14#appendix-B.1


## CBOR Diagnostic
    / SUIT_Envelope = /
    107({
        / authentication-wrapper / 2 : <<[
            / digest : / <<[
                / algorithm-id / 2 / sha256 /,
                / digest-bytes / h'5c097ef64bf3bb9b494e71e1f2418eef8d466cc902f639a855ec9af3e9eddb99'
            ]>>,
            / signature : / <<18([
                / protected / <<{
                    / alg / 1 : -7 / ES256 /,
                }>>,
                / unprotected / {
                },
                / payload / nil,
                / signature / h'd11a2dd9610fb62a707335f584079225709f96e8117e7eeed98a2f207d05c8ecfba1755208f6abea977b8a6efe3bc2ca3215e1193be201467d052b42db6b7287'
            ])>>
        ]),
        / manifest / 3 : <<{
            / manifest-version / 1 : 1,
            / manifest-sequence-number / 2 : 0,
            / common / 3 : <<{
                / components / 2 : [
                    [h'00']
                ],
                / common-sequence / 4 : <<[
                    / directive-override-parameters / 20,
                    {
                        / vendor-id / 1 : h'fa6b4a53d5ad5fdfbe9de663e4d41ffe' / fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe /,
                        / class-id / 2 : h'1492af1425695e48bf429b2d51f2ab45' / 1492af14-2569-5e48-bf42-9b2d51f2ab45 /,
                        / image-digest / 3 : <<[
                            / algorithm-id / -16 / sha256 /,
                            / digest-bytes / h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
                        ]>>,
                        / image-size / 14 : 34768,
                    },
                    / condition-vendor-identifier / 1, 15,
                    / condition-class-identifier / 2, 15
                ]>>,
            }>>,
            / validate / 10 : <<[
                / condition-image-match / 3, 15
            ]>>,
            / run / 12 : <<[
                / directive-run / 23, 2
            ]>>,
        }),
    })


## CBOR binary
    D8 6B                                   # tag(107)
       A2                                   # map(2)
          02                                # unsigned(2)
          58 73                             # bytes(115)
             825824822F5820A6C4590AC53043A98E8C4106E1E31B305516D7CF0A655EDDFAC6D45C810E036A584AD28443A10126A0F65840D11A2DD9610FB62A707335F584079225709F96E8117E7EEED98A2F207D05C8ECFBA1755208F6ABEA977B8A6EFE3BC2CA3215E1193BE201467D052B42DB6B7287
          03                                # unsigned(3)
          58 71                             # bytes(113)
             A50101020003585FA202818141000458568614A40150FA6B4A53D5AD5FDFBE9DE663E4D41FFE02501492AF1425695E48BF429B2D51F2AB45035824822F582000112233445566778899AABBCCDDEEFF0123456789ABCDEFFEDCBA98765432100E1987D0010F020F0A4382030F0C43821702


## CBOR binary (extracted)
    D8 6B                                      # tag(107)
       A2                                      # map(2)
          02                                   # unsigned(2) / authentication-wrapper : /
          58 73                                # bytes(115)
             # SUIT_Authentication #
             82                                # array(2)
                58 24                          # bytes(36)
                   # SUIT_Digest #
                   82                          # array(2)
                      2F                       # negative(15) / algorithm-id : sha256 /
                      58 20                    # bytes(32)   / digest-bytes /
                         A6C4590AC53043A98E8C4106E1E31B305516D7CF0A655EDDFAC6D45C810E036A
                 58 4A                         # bytes(74)
                    D2                         # tag(18) / COSE_Sign1 /
                       84                      # array(4)
                          43                   # bytes(3)
                             # protected #
                             A1                # map(1)
                                01             # unsigned(1) / alg : /
                                26             # negative(6) / -7 /
                          A0                   # map(0)
                          F6                   # primitive(22) / null /
                          58 40                # bytes(64) / signature /
                             D11A2DD9610FB62A707335F584079225709F96E8117E7EEED98A2F207D05C8ECFBA1755208F6ABEA977B8A6EFE3BC2CA3215E1193BE201467D052B42DB6B7287
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
                                     2F        # negative(15) / algorithm-id : sha256 /
                                     58 20     # bytes(32)    / digest-bytes /
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
    echo -en "\xD8\x6B\xA2\x02\x58\x73\x82\x58\x24\x82\x2F\x58\x20\xA6\xC4\x59\x0A\xC5\x30\x43\xA9\x8E\x8C\x41\x06\xE1\xE3\x1B\x30\x55\x16\xD7\xCF\x0A\x65\x5E\xDD\xFA\xC6\xD4\x5C\x81\x0E\x03\x6A\x58\x4A\xD2\x84\x43\xA1\x01\x26\xA0\xF6\x58\x40\xD1\x1A\x2D\xD9\x61\x0F\xB6\x2A\x70\x73\x35\xF5\x84\x07\x92\x25\x70\x9F\x96\xE8\x11\x7E\x7E\xEE\xD9\x8A\x2F\x20\x7D\x05\xC8\xEC\xFB\xA1\x75\x52\x08\xF6\xAB\xEA\x97\x7B\x8A\x6E\xFE\x3B\xC2\xCA\x32\x15\xE1\x19\x3B\xE2\x01\x46\x7D\x05\x2B\x42\xDB\x6B\x72\x87\x03\x58\x71\xA5\x01\x01\x02\x00\x03\x58\x5F\xA2\x02\x81\x81\x41\x00\x04\x58\x56\x86\x14\xA4\x01\x50\xFA\x6B\x4A\x53\xD5\xAD\x5F\xDF\xBE\x9D\xE6\x63\xE4\xD4\x1F\xFE\x02\x50\x14\x92\xAF\x14\x25\x69\x5E\x48\xBF\x42\x9B\x2D\x51\xF2\xAB\x45\x03\x58\x24\x82\x2F\x58\x20\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x0E\x19\x87\xD0\x01\x0F\x02\x0F\x0A\x43\x82\x03\x0F\x0C\x43\x82\x17\x02" > suit_manifest_exp0.cbor
