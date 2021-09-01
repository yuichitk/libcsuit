<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    B.2.  Example 1: Simultaneous Download and Installation of Payload
    https://tools.ietf.org/html/draft-ietf-suit-manifest-14#appendix-B.2


## CBOR Diagnostic
    / SUIT_Envelope = /
    107({
        / authentication-wrapper / 2 : <<[
            / digest / <<[
                / algorithm-id / -16 / sha256 /,
                / digest-bytes / h'60c61d6eb7a1aaeddc49ce8157a55cff0821537eeee77a4ded44155b03045132'
            ]>>,
            / signature / <<18([
                / protected / <<{
                    / alg / 1 : -7 / ES256 /,
                }>>,
                / unprotected / {
                },
                / payload / nil,
                / signature / h'5249dacaf0ffc8326931b09586eb7e3769e71a0e6a40ad8153db4980db9b05bd1742ddb46085fa11e62b65a79895c12ac7abe2668ccc5afdd74466aed7bca389'
            ])>>
        ]>>,
        / manifest / 3 : <<{
            / manifest-version / 1 : 1,
            / manifest-sequence-number / 2 : 1,
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
            / install / 9 : <<[
                / directive-set-parameters / 19,
                {
                    / uri / 21:'http://example.com/file.bin',
                },
                / directive-fetch / 21, 2,
                / condition-image-match / 3, 15
            ]>>,
            / validate / 10 : <<[
                / condition-image-match / 3, 15
            ]>>,
        }>>,
    })


## CBOR binary
    D8 6B                                   # tag(107)
       A2                                   # map(2)
          02                                # unsigned(2)
          58 73                             # bytes(115)
             825824822F582060C61D6EB7A1AAEDDC49CE8157A55CFF0821537EEEE77A4DED44155B03045132584AD28443A10126A0F658405249DACAF0FFC8326931B09586EB7E3769E71A0E6A40AD8153DB4980DB9B05BD1742DDB46085FA11E62B65A79895C12AC7ABE2668CCC5AFDD74466AED7BCA389
          03                                # unsigned(3)
          58 94                             # bytes(148)
             A50101020103585FA202818141000458568614A40150FA6B4A53D5AD5FDFBE9DE663E4D41FFE02501492AF1425695E48BF429B2D51F2AB45035824822F582000112233445566778899AABBCCDDEEFF0123456789ABCDEFFEDCBA98765432100E1987D0010F020F0958258613A115781B687474703A2F2F6578616D706C652E636F6D2F66696C652E62696E1502030F0A4382030F


## CBOR binary (extracted)
    D8 6B                                      # tag(107) / SUIT_Envelope /
       A2                                      # map(2)
          02                                   # unsigned(2) / suit-authentication-wrapper : /
          58 98                                # bytes(152)
             # SUIT_Authentication #
             82                                # array(2)
                58 24                          # bytes(36)
                   # SUIT_Digest #
                   82                          # array(2)
                      2F                       # negative(15) / algorithm-id : sha256 /
                      58 20                    # bytes(32) / digest-bytes /
                         60C61D6EB7A1AAEDDC49CE8157A55CFF0821537EEEE77A4DED44155B03045132
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
                         F6                    # null
                         58 40                 # bytes(64)   / signature /
                            5249DACAF0FFC8326931B09586EB7E3769E71A0E6A40AD8153DB4980DB9B05BD1742DDB46085FA11E62B65A79895C12AC7ABE2668CCC5AFDD74466AED7BCA389
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
                         # SUIT_Command_Sequence #
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
                                     2F        # negative(15) / algorithm-id : sha256 /
                                     58 20     # bytes(32)    / digest-bytes : /
                                        00112233445566778899AABBCCDDEEFF0123456789ABCDEFFEDCBA9876543210
                               0E              # unsigned(14)    / image-size : /
                               19 87D0         # unsigned(34768)
                            01                 # unsigned(1)  / condition-vendor-identifier : 15 /
                            0F                 # unsigned(15)
                            02                 # unsigned(2)  / condition-class-identifier : 15 /
                            0F                 # unsigned(15)
                09                             # unsigned(9)  / install : /
                58 25                          # bytes(37)
                   # SUIT_Command_Sequence #
                   86                          # array(6)
                      13                       # unsigned(19) / directive-set-parameters : /
                      A1                       # map(1)
                         15                    # unsigned(21) / uri : /
                         78 1B                 # text(27) / "http://example.com/file.bin" /
                            687474703A2F2F6578616D706C652E636F6D2F66696C652E62696E
                      15                       # unsigned(21) / directive-fetch : /
                      02                       # unsigned(2)
                      03                       # unsigned(3)  / condition-image-match : /
                      0F                       # unsigned(15)
                0A                             # unsigned(10) / validate : /
                43                             # bytes(3)
                   # SUIT_Command_Sequence #
                   82                          # array(2)
                      03                       # unsigned(3)  / condition-image-match : /
                      0F                       # unsigned(15)


## Command
    echo -en "\xD8\x6B\xA2\x02\x58\x73\x82\x58\x24\x82\x2F\x58\x20\x60\xC6\x1D\x6E\xB7\xA1\xAA\xED\xDC\x49\xCE\x81\x57\xA5\x5C\xFF\x08\x21\x53\x7E\xEE\xE7\x7A\x4D\xED\x44\x15\x5B\x03\x04\x51\x32\x58\x4A\xD2\x84\x43\xA1\x01\x26\xA0\xF6\x58\x40\x52\x49\xDA\xCA\xF0\xFF\xC8\x32\x69\x31\xB0\x95\x86\xEB\x7E\x37\x69\xE7\x1A\x0E\x6A\x40\xAD\x81\x53\xDB\x49\x80\xDB\x9B\x05\xBD\x17\x42\xDD\xB4\x60\x85\xFA\x11\xE6\x2B\x65\xA7\x98\x95\xC1\x2A\xC7\xAB\xE2\x66\x8C\xCC\x5A\xFD\xD7\x44\x66\xAE\xD7\xBC\xA3\x89\x03\x58\x94\xA5\x01\x01\x02\x01\x03\x58\x5F\xA2\x02\x81\x81\x41\x00\x04\x58\x56\x86\x14\xA4\x01\x50\xFA\x6B\x4A\x53\xD5\xAD\x5F\xDF\xBE\x9D\xE6\x63\xE4\xD4\x1F\xFE\x02\x50\x14\x92\xAF\x14\x25\x69\x5E\x48\xBF\x42\x9B\x2D\x51\xF2\xAB\x45\x03\x58\x24\x82\x2F\x58\x20\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x0E\x19\x87\xD0\x01\x0F\x02\x0F\x09\x58\x25\x86\x13\xA1\x15\x78\x1B\x68\x74\x74\x70\x3A\x2F\x2F\x65\x78\x61\x6D\x70\x6C\x65\x2E\x63\x6F\x6D\x2F\x66\x69\x6C\x65\x2E\x62\x69\x6E\x15\x02\x03\x0F\x0A\x43\x82\x03\x0F" > suit_manifest_exp1.cbor
