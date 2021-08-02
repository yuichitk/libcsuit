<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    B.6.  Example 5: Two Images
    https://tools.ietf.org/html/draft-ietf-suit-manifest-14#appendix-B.6


## CBOR Diagnostic
    / SUIT_Envelope = /
    107({
        / authentication-wrapper / 2 : <<[
            / digest / <<[
                / algorithm-id / -16 / sha256 /,
                / digest-bytes / h'd1e73f16e4126007bc4d804cd33b0209fbab34728e60ee8c00f3387126748dd2'
            ]>>,
            / signatures / <<18([
                / protected / <<{
                    / alg / 1:-7 / ES256 /,
                }>>,
                / unprotected / {
                },
                / payload / nil,
                / signature / h'b7ae0a46a28f02e25cda6d9a255bbaf86330141831fae5a78012d648bc6cee55102e0f1890bdeacc3adaa4fae0560f83a45eecae65cabce642f56d84ab97ef8d'
            ])>>
        ]>>,
        / manifest / 3 : <<{
            / manifest-version / 1 : 1,
            / manifest-sequence-number / 2 : 5,
            / common / 3 : <<{
                / components / 2 : [
                    [h'00'] ,
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
                    / condition-class-identifier / 2, 15,
                    / directive-set-component-index / 12, 1,
                    / directive-override-parameters / 20,
                    {
                        / image-digest / 3 : <<[
                            / algorithm-id / -16 / sha256 /,
                            / digest-bytes / h'0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff'
                        ]>>,
                        / image-size / 14 : 76834,
                    }
                ]>>,
            }>>,
            / install / 9 : <<[
                / directive-set-component-index / 12, 0,
                / directive-set-parameters / 19,
                {
                    / uri / 21 : 'http://example.com/file1.bin',
                } ,
                / directive-fetch / 21, 2,
                / condition-image-match / 3, 15,
                / directive-set-component-index / 12, 1,
                / directive-set-parameters / 19,
                {
                    / uri / 21 : 'http://example.com/file2.bin',
                },
                / directive-fetch / 21, 2,
                / condition-image-match / 3, 15
            ]>>,
            / validate / 10 : <<[
                / directive-set-component-index / 12, 0,
                / condition-image-match / 3, 15,
                / directive-set-component-index / 12, 1,
                / condition-image-match / 3, 15
            ]>>,
            / run / 12 : <<[
                / directive-set-component-index / 12, 0,
                / directive-run / 23, 2
            ]>>,
        }>>,
    })


## CBOR binary
    D8 6B                                   # tag(107)
       A2                                   # map(2)
          02                                # unsigned(2)
          58 73                             # bytes(115)
             825824822F5820D1E73F16E4126007BC4D804CD33B0209FBAB34728E60EE8C00F3387126748DD2584AD28443A10126A0F65840B7AE0A46A28F02E25CDA6D9A255BBAF86330141831FAE5A78012D648BC6CEE55102E0F1890BDEACC3ADAA4FAE0560F83A45EECAE65CABCE642F56D84AB97EF8D
          03                                # unsigned(3)
          59 0101                           # bytes(257)
             A601010205035895A202828141008141010458898C0C0014A40150FA6B4A53D5AD5FDFBE9DE663E4D41FFE02501492AF1425695E48BF429B2D51F2AB45035824822F582000112233445566778899AABBCCDDEEFF0123456789ABCDEFFEDCBA98765432100E1987D0010F020F0C0114A2035824822F58200123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF0E1A00012C2209584F900C0013A115781C687474703A2F2F6578616D706C652E636F6D2F66696C65312E62696E1502030F0C0113A115781C687474703A2F2F6578616D706C652E636F6D2F66696C65322E62696E1502030F0A49880C00030F0C01030F0C45840C001702


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
                         D1E73F16E4126007BC4D804CD33B0209FBAB34728E60EE8C00F3387126748DD2
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
                            B7AE0A46A28F02E25CDA6D9A255BBAF86330141831FAE5A78012D648BC6CEE55102E0F1890BDEACC3ADAA4FAE0560F83A45EECAE65CABCE642F56D84AB97EF8D
          03                                   # unsigned(3) / manifest : /
          59 0101                              # bytes(257)
             # SUIT_Manifest #
             A6                                # map(6)
                01                             # unsigned(1) / manifest-version : /
                01                             # unsigned(1)
                02                             # unsigned(2) / manifest-sequence-number : /
                05                             # unsigned(5)
                03                             # unsigned(3) / common : /
                58 95                          # bytes(149)
                   # SUIT_Common #
                   A2                          # map(2)
                      02                       # unsigned(2) / components : /
                      82                       # array(2)
                         81                    # array(1)    / [h'00']
                            41                 # bytes(1)
                               00              # "\x00"
                         81                    # array(1)    / [h'01']
                            41                 # bytes(1)
                               01              # "\x01"
                      04                       # unsigned(4) / common-sequence : /
                      58 89                    # bytes(137)
                         # SUIT_Common_Sequence #
                         8C                    # array(12)
                            0C                 # unsigned(12) / directive-set-component-index : /
                            00                 # unsigned(0)
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
                            01                 # unsigned(1) / condition-vendor-identifier : /
                            0F                 # unsigned(15)
                            02                 # unsigned(2) / condition-class-identifier : /
                            0F                 # unsigned(15)
                            0C                 # unsigned(12) / directive-set-component-index : /
                            01                 # unsigned(1)
                            14                 # unsigned(20) / directive-override-parameters : /
                            A2                 # map(2)
                               03              # unsigned(3)  / image-digest : /
                               58 24           # bytes(36)
                                  # SUIT_Digest #
                                  82           # array(2)
                                     2F        # negative(15) / algorithm-id : sha256 /
                                     58 20     # bytes(32)    / digest-bytes /
                                        0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF
                               0E              # unsigned(14) / image-size : /
                               1A 00012C22     # unsigned(76834)
                09                             # unsigned(9) / install : /
                58 4F                          # bytes(79)
                   # SUIT_Common_Sequence #
                   90                          # array(16)
                      0C                       # unsigned(12) / directive-set-component-index : /
                      00                       # unsigned(0)
                      13                       # unsigned(19) / directive-set-parameters : /
                      A1                       # map(1)
                         15                    # unsigned(21) / uri : /
                         78 1C                 # text(28)     / "http://example.com/file1.bin" /
                            687474703A2F2F6578616D706C652E636F6D2F66696C65312E62696E
                      15                       # unsigned(21) / directive-fetch : /
                      02                       # unsigned(2)
                      03                       # unsigned(3)  / condition-image-match : /
                      0F                       # unsigned(15)
                      0C                       # unsigned(12) / directive-set-component-index : /
                      01                       # unsigned(1)
                      13                       # unsigned(19) / directive-set-parameters : /
                      A1                       # map(1)
                         15                    # unsigned(21) / uri : /
                         78 1C                 # text(28)     / "http://example.com/file2.bin" /
                            687474703A2F2F6578616D706C652E636F6D2F66696C65322E62696E
                      15                       # unsigned(21) / directive-fetch : /
                      02                       # unsigned(2)
                      03                       # unsigned(3)  / condition-image-match : /
                      0F                       # unsigned(15)
                0A                             # unsigned(10) / validate : /
                49                             # bytes(9)
                   # SUIT_Common_Sequence #
                   88                          # array(8)
                      0C                       # unsigned(12) / directive-set-component-index : /
                      00                       # unsigned(0)
                      03                       # unsigned(3)  / condition-image-match : /
                      0F                       # unsigned(15)
                      0C                       # unsigned(12) / directive-set-component-index : /
                      01                       # unsigned(1)
                      03                       # unsigned(3)  / condition-image-match : /
                      0F                       # unsigned(3)
                0C                             # unsigned(12) / run : /
                45                             # bytes(5)
                   # SUIT_Common_Sequence #
                   84                          # array(4)
                      0C                       # unsigned(12) / directive-set-component-index : /
                      00                       # unsigned(0)
                      17                       # unsigned(23) / directive-run : /
                      02                       # unsigned(2)


## Command
    echo -en "\xD8\x6B\xA2\x02\x58\x73\x82\x58\x24\x82\x2F\x58\x20\xD1\xE7\x3F\x16\xE4\x12\x60\x07\xBC\x4D\x80\x4C\xD3\x3B\x02\x09\xFB\xAB\x34\x72\x8E\x60\xEE\x8C\x00\xF3\x38\x71\x26\x74\x8D\xD2\x58\x4A\xD2\x84\x43\xA1\x01\x26\xA0\xF6\x58\x40\xB7\xAE\x0A\x46\xA2\x8F\x02\xE2\x5C\xDA\x6D\x9A\x25\x5B\xBA\xF8\x63\x30\x14\x18\x31\xFA\xE5\xA7\x80\x12\xD6\x48\xBC\x6C\xEE\x55\x10\x2E\x0F\x18\x90\xBD\xEA\xCC\x3A\xDA\xA4\xFA\xE0\x56\x0F\x83\xA4\x5E\xEC\xAE\x65\xCA\xBC\xE6\x42\xF5\x6D\x84\xAB\x97\xEF\x8D\x03\x59\x01\x01\xA6\x01\x01\x02\x05\x03\x58\x95\xA2\x02\x82\x81\x41\x00\x81\x41\x01\x04\x58\x89\x8C\x0C\x00\x14\xA4\x01\x50\xFA\x6B\x4A\x53\xD5\xAD\x5F\xDF\xBE\x9D\xE6\x63\xE4\xD4\x1F\xFE\x02\x50\x14\x92\xAF\x14\x25\x69\x5E\x48\xBF\x42\x9B\x2D\x51\xF2\xAB\x45\x03\x58\x24\x82\x2F\x58\x20\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x0E\x19\x87\xD0\x01\x0F\x02\x0F\x0C\x01\x14\xA2\x03\x58\x24\x82\x2F\x58\x20\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x0E\x1A\x00\x01\x2C\x22\x09\x58\x4F\x90\x0C\x00\x13\xA1\x15\x78\x1C\x68\x74\x74\x70\x3A\x2F\x2F\x65\x78\x61\x6D\x70\x6C\x65\x2E\x63\x6F\x6D\x2F\x66\x69\x6C\x65\x31\x2E\x62\x69\x6E\x15\x02\x03\x0F\x0C\x01\x13\xA1\x15\x78\x1C\x68\x74\x74\x70\x3A\x2F\x2F\x65\x78\x61\x6D\x70\x6C\x65\x2E\x63\x6F\x6D\x2F\x66\x69\x6C\x65\x32\x2E\x62\x69\x6E\x15\x02\x03\x0F\x0A\x49\x88\x0C\x00\x03\x0F\x0C\x01\x03\x0F\x0C\x45\x84\x0C\x00\x17\x02" > suit_manifest_exp5.cbor
