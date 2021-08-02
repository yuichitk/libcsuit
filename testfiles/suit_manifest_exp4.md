<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    B.5.  Example 4: Load and Decompress from External Storage
    https://tools.ietf.org/html/draft-ietf-suit-manifest-14#appendix-B.5


## CBOR Diagnostic
    / SUIT_Envelope = /
    107({
        / authentication-wrapper / 2 : <<[
            / digest / <<[
                / algorithm-id / -16 / sha256 /,
                / digest-bytes / h'15736702a00f510805dcf89d6913a2cfb417ed414faa760f974d6755c68ba70a'
            ]>>,
            / signature / <<18([
                / protected / <<{
                    / alg / 1:-7 / ES256 /,
                }>>,
                / unprotected / {
                },
                / payload / nil,
                / signature / h'3ada2532326d512132c388677798c24ffdcc979bfae2a26b19c8c8bbf511fd7dd85f1501662c1a9e1976b759c4019bab44ba5434efb45d3868aedbca593671f3'
            ])>>
        ]>>,
        / manifest / 3 : <<{
            / manifest-version / 1 : 1,
            / manifest-sequence-number / 2 : 4,
            / common / 3 : <<{
                / components / 2 : [
                    [h'00'] ,
                    [h'02'] ,
                    [h'01']
                ],
                / common-sequence / 4 : <<[
                    / directive-set-component-index / 12, 0,
                    / directive-override-parameters / 20,
                    {
                        / vendor-id / 1 : h'fa6b4a53d5ad5fdfbe9de663e4d41ffe' / fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe /,
                        / class-id / 2 : h'1492af1425695e48bf429b2d51f2ab45' / 1492af14-2569-5e48-bf42-9b2d51f2ab45 /,
                        / image-digest / 3 : <<[
                            / algorithm-id / -16 / sha256 /,
                            / digest-bytes / h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
                        ]>>,
                        / image-size / 14 : 34768,
                    } ,
                    / condition-vendor-identifier / 1, 15,
                    / condition-class-identifier / 2, 15
                ]>>,
            }>>,
            / payload-fetch / 8 : <<[
                / directive-set-component-index / 12, 1,
                / directive-set-parameters / 19,
                {
                    / uri / 21 : 'http://example.com/file.bin',
                } ,
                / directive-fetch / 21, 2 ,
                / condition-image-match / 3, 15
            ]>>,
            / install / 9 : <<[
                / directive-set-component-index / 12, 0,
                / directive-set-parameters / 19,
                {
                    / source-component / 22 : 1 / [h'02'] /,
                },
                / directive-copy / 22, 2,
                / condition-image-match / 3, 15
            ]>>,
            / validate / 10 : <<[
                / directive-set-component-index / 12, 0,
                / condition-image-match / 3, 15
            ]>>,
            / load / 11 : <<[
                / directive-set-component-index / 12, 2,
                / directive-set-parameters / 19,
                {
                    / image-digest / 3 : <<[
                        / algorithm-id / -16 / sha256 /,
                        / digest-bytes / h'0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff'
                    ]>>,
                    / image-size / 14 : 76834,
                    / source-component / 22 : 0 / [h'00'] /,
                    / compression-info / 19,
                    <<{
                        / compression-algorithm / 1 : 1 / "gzip" /
                    }>>
                },
                / directive-copy / 22, 2,
                / condition-image-match / 3, 15
            ]>>,
            / run / 12 : <<[
                / directive-set-component-index / 12, 2,
                / directive-run / 23, 2
            ]>>,
        }>>,
    })


## CBOR binary
    D8 6B                                   # tag(107)
       A2                                   # map(2)
          02                                # unsigned(2)
          58 73                             # bytes(115)
             825824822F582015736702A00F510805DCF89D6913A2CFB417ED414FAA760F974D6755C68BA70A584AD28443A10126A0F658403ADA2532326D512132C388677798C24FFDCC979BFAE2A26B19C8C8BBF511FD7DD85F1501662C1A9E1976B759C4019BAB44BA5434EFB45D3868AEDBCA593671F3
          03                                # unsigned(3)
          58 F4                             # bytes(244)
             A801010204035867A20283814100814102814101045858880C0014A40150FA6B4A53D5AD5FDFBE9DE663E4D41FFE02501492AF1425695E48BF429B2D51F2AB45035824822F582000112233445566778899AABBCCDDEEFF0123456789ABCDEFFEDCBA98765432100E1987D0010F020F085827880C0113A115781B687474703A2F2F6578616D706C652E636F6D2F66696C652E62696E1502030F094B880C0013A116011602030F0A45840C00030F0B583D880C0213A4035824822F58200123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF0E1A00012C221343A1010116001602030F0C45840C021702


## CBOR binary (extracted)
    D8 6B                                      # tag(107) / SUIT_Envelope /
       A2                                      # map(2)
          02                                   # unsigned(2) / suit-authentication-wrapper : /
          58 73                                # bytes(115)
             # SUIT_Authentication #
             82                                # array(2)
                58 24                          # bytes(36)
                   # SUIT_Digest #
                   82                          # array(2)
                      2F                       # negative(15) / algorithm-id : sha256 /
                      58 20                    # bytes(32)    / digest-bytes /
                         15736702A00F510805DCF89D6913A2CFB417ED414FAA760F974D6755C68BA70A
                58 4A                          # bytes(74)
                   # SUIT_Authentication_Block #
                   D2                          # tag(18) / COSE_Sign1 /
                      84                       # array(4)
                         43                    # bytes(3)
                            # protected #
                            A1                 # map(1)
                               01              # unsigned(1) / alg /
                               26              # negative(6) / -7 /
                         A0                    # map(0)
                         F6                    # primitive(22) / null /
                         58 40                 # bytes(64) / signature /
                            3ADA2532326D512132C388677798C24FFDCC979BFAE2A26B19C8C8BBF511FD7DD85F1501662C1A9E1976B759C4019BAB44BA5434EFB45D3868AEDBCA593671F3
          03                                   # unsigned(3) / manifest : /
          58 F4                                # bytes(244)
             # SUIT_Manifest #
             A8                                # map(8)
                01                             # unsigned(1) / manifest-version : /
                01                             # unsigned(1)
                02                             # unsigned(2) / manifest-sequence-number : /
                04                             # unsigned(4)
                03                             # unsigned(3) / common : /
                58 67                          # bytes(103)
                   # SUIT_Common #
                   A2                          # map(2)
                      02                       # unsigned(2) / components : /
                      83                       # array(3)
                         81                    # array(1)    / [h'00'] /
                            41                 # bytes(1)
                               00              # "\x00"
                         81                    # array(1)    / [h'02'] /
                            41                 # bytes(1)
                               02              # "\x02"
                         81                    # array(1)    / [h'01'] /
                            41                 # bytes(1)
                               01              # "\x01"
                      04                       # unsigned(4) / common-sequence : /
                      58 58                    # bytes(88)
                         # SUIT_Common_Sequence #
                         88                    # array(8)
                            0C                 # unsigned(12) / directive-set-componet-index : /
                            00                 # unsigned(0)
                            14                 # unsigned(20) / directive-override-parameters : /
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
                                     2F        # negative(15) / algorithm-id : sha256 /
                                     58 20     # bytes(32)    / digest-bytes /
                                        00112233445566778899AABBCCDDEEFF0123456789ABCDEFFEDCBA9876543210
                               0E              # unsigned(14) / image-size : /
                               19 87D0         # unsigned(34768)
                            01                 # unsigned(1)  / condition-vendor-identifier : /
                            0F                 # unsigned(15)
                            02                 # unsigned(2)  / condition-class-identifier : /
                            0F                 # unsigned(15)
                08                             # unsigned(8) / payload-fetch : /
                58 27                          # bytes(39)
                   # SUIT_Common_Sequence #
                   88                          # array(8)
                      0C                       # unsigned(12) / directive-set-component-index : /
                      01                       # unsigned(1)
                      13                       # unsigned(19) / directive-set-parameters : /
                      A1                       # map(1)
                         15                    # unsigned(21) / uri : /
                         78 1B                 # text(27)     / "http://example.com/file.bin" /
                            687474703A2F2F6578616D706C652E636F6D2F66696C652E62696E
                      15                       # unsigned(21) / directive-fetch : /
                      02                       # unsigned(2)
                      03                       # unsigned(3)  / condition-image-match : /
                      0F                       # unsigned(15)
                09                             # unsigned(9) / install : /
                4B                             # bytes(11)
                   # SUIT_Common_Sequence #
                   88                          # array(8)
                      0C                       # unsigned(12) / directive-set-component-index : /
                      00                       # unsigned(0)
                      13                       # unsigned(19) / directive-set-parameters : /
                      A1                       # map(1)
                         16                    # unsigned(22) / source-component : /
                         01                    # unsigned(1)  / 1 = [h'02'] /
                      16                       # unsigned(22) / directive-copy : /
                      02                       # unsigned(2)
                      03                       # unsigned(3)  / condition-image-match : /
                      0F                       # unsigned(15)
                0A                             # unsigned(10) / validate : /
                45                             # bytes(5)
                   # SUIT_Common_Sequence #
                   84                          # array(4)
                      0C                       # unsigned(12) / directive-set-componet-indes : /
                      00                       # unsigned(0)
                      03                       # unsigned(3)  / condition-image-match : /
                      0F                       # unsigned(15)
                0B                             # unsigned(11) / load : /
                58 3D                          # bytes(61)
                   # SUIT_Common_Sequence #
                   88                          # array(8)
                      0C                       # unsigned(12) / directive-set-component-index : /
                      02                       # unsigned(2)
                      13                       # unsigned(19) / directive-set-parameters : /
                      A4                       # map(4)
                         03                    # unsigned(3)  / image-digest : /
                         58 24                 # bytes(36)
                            # SUIT_Digest #
                            82                 # array(2)
                               2F              # negative(15) / algorithm-id : sha256 /
                               58 20           # bytes(32)    / digest-bytes /
                                  0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF
                         0E                    # unsigned(14) / image-size : /
                         1A 00012C22           # unsigned(76834)
                         13                    # unsigned(19) / compression-info : /
                         43                    # bytes(3)
                            A1                 # map(1)
                               01              # unsigned(1)  / compression-algorithm : /
                               01              # unsigned(1)  / zlib /
                         16                    # unsigned(22) / source-component : /
                         00                    # unsigned(0)  / 0 = [h'00'] /
                      16                       # unsigned(22) / directive-copy : /
                      02                       # unsigned(2)
                      03                       # unsigned(3)  / condition-image-match : /
                      0F                       # unsigned(15)
                0C                             # unsigned(12) / run : /
                45                             # bytes(5)
                   # SUIT_Common_Sequence #
                   84                          # array(4)
                      0C                       # unsigned(12) / directive-set-component-index : /
                      02                       # unsigned(2)
                      17                       # unsigned(23) / directive-run : /
                      02                       # unsigned(2)


## Command
    echo -en "\xD8\x6B\xA2\x02\x58\x73\x82\x58\x24\x82\x2F\x58\x20\x15\x73\x67\x02\xA0\x0F\x51\x08\x05\xDC\xF8\x9D\x69\x13\xA2\xCF\xB4\x17\xED\x41\x4F\xAA\x76\x0F\x97\x4D\x67\x55\xC6\x8B\xA7\x0A\x58\x4A\xD2\x84\x43\xA1\x01\x26\xA0\xF6\x58\x40\x3A\xDA\x25\x32\x32\x6D\x51\x21\x32\xC3\x88\x67\x77\x98\xC2\x4F\xFD\xCC\x97\x9B\xFA\xE2\xA2\x6B\x19\xC8\xC8\xBB\xF5\x11\xFD\x7D\xD8\x5F\x15\x01\x66\x2C\x1A\x9E\x19\x76\xB7\x59\xC4\x01\x9B\xAB\x44\xBA\x54\x34\xEF\xB4\x5D\x38\x68\xAE\xDB\xCA\x59\x36\x71\xF3\x03\x58\xF4\xA8\x01\x01\x02\x04\x03\x58\x67\xA2\x02\x83\x81\x41\x00\x81\x41\x02\x81\x41\x01\x04\x58\x58\x88\x0C\x00\x14\xA4\x01\x50\xFA\x6B\x4A\x53\xD5\xAD\x5F\xDF\xBE\x9D\xE6\x63\xE4\xD4\x1F\xFE\x02\x50\x14\x92\xAF\x14\x25\x69\x5E\x48\xBF\x42\x9B\x2D\x51\xF2\xAB\x45\x03\x58\x24\x82\x2F\x58\x20\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x0E\x19\x87\xD0\x01\x0F\x02\x0F\x08\x58\x27\x88\x0C\x01\x13\xA1\x15\x78\x1B\x68\x74\x74\x70\x3A\x2F\x2F\x65\x78\x61\x6D\x70\x6C\x65\x2E\x63\x6F\x6D\x2F\x66\x69\x6C\x65\x2E\x62\x69\x6E\x15\x02\x03\x0F\x09\x4B\x88\x0C\x00\x13\xA1\x16\x01\x16\x02\x03\x0F\x0A\x45\x84\x0C\x00\x03\x0F\x0B\x58\x3D\x88\x0C\x02\x13\xA4\x03\x58\x24\x82\x2F\x58\x20\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x0E\x1A\x00\x01\x2C\x22\x13\x43\xA1\x01\x01\x16\x00\x16\x02\x03\x0F\x0C\x45\x84\x0C\x02\x17\x02" > suit_manifest_exp4.cbor
