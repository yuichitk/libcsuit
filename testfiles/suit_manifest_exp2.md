<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    B.3.  Example 2: Simultaneous Download, Installation, Secure Boot, Severed Fields
    https://tools.ietf.org/html/draft-ietf-suit-manifest-14#appendix-B.3


## CBOR Diagnostic
    / SUIT_Envelope = /
    107({
        / authentication-wrapper / 2 : <<[
            / digest / <<[
                / algorithm-id / -16 / sha256 /,
                / digest-bytes / h'e45dcdb2074b951f1c88b866469939c2a83ed433a31fc7dfcb3f63955bd943ec'
            ]>>,
            / signature / <<18([
                / protected / <<{
                    / alg / 1 : -7 / ES256 /,
                }>>,
                / unprotected / {
                },
                / payload / nil,
                / signature / h'b4fd3a6a18fe1062573488cf24ac96ef9f30ac746696e50be96533b356b8156e4332587fe6f4e8743ae525d72005fddd4c1213d55a8061b2ce67b83640f4777c'
            ])>>
        ]>>,
        / manifest / 3 : <<{
            / manifest-version / 1 : 1,
            / manifest-sequence-number / 2 : 2,
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
                / algorithm-id / -16 / sha256 /,
                / digest-bytes / h'3ee96dc79641970ae46b929ccf0b72ba9536dd846020dbdc9f949d84ea0e18d2'
            ]>>,
            / validate / 10 : <<[
                / condition-image-match / 3, 15
            ]>>,
            / run / 12 : <<[
                / directive-run / 23, 2
            ]>>,
            / text / 13 : <<[
                / algorithm-id / -16 / sha256 /,
                / digest-bytes / h'2bfc4d0cc6680be7dd9f5ca30aa2bb5d1998145de33d54101b80e2ca49faf918'
            ]>>,
        }>>,
        / install / 9 : <<[
            / directive-set-parameters / 19,
            {
              / uri / 21 : 'http://example.com/very/long/path/to/file/file.bin',
            },
            / directive-fetch / 21, 2,
            / condition-image-match / 3, 15
        ]>>,
        / text / 13 : <<{
            [h'00'] : {
                / vendor-domain / 3 : 'arm.com',
                / component-description / 5 : 'This component is a demonstration. The digest is a sample pattern, not a real one.',
            }
        }>>,
    })


## CBOR Binary
    D8 6B                                   # tag(107)
       A4                                   # map(4)
          02                                # unsigned(2)
          58 73                             # bytes(115)
             825824822F5820E45DCDB2074B951F1C88B866469939C2A83ED433A31FC7DFCB3F63955BD943EC584AD28443A10126A0F65840B4FD3A6A18FE1062573488CF24AC96EF9F30AC746696E50BE96533B356B8156E4332587FE6F4E8743AE525D72005FDDD4C1213D55A8061B2CE67B83640F4777C
          03                                # unsigned(3)
          58 BB                             # bytes(187)
             A70101020203585FA202818141000458568614A40150FA6B4A53D5AD5FDFBE9DE663E4D41FFE02501492AF1425695E48BF429B2D51F2AB45035824822F582000112233445566778899AABBCCDDEEFF0123456789ABCDEFFEDCBA98765432100E1987D0010F020F09822F58203EE96DC79641970AE46B929CCF0B72BA9536DD846020DBDC9F949D84EA0E18D20A4382030F0C438217020D822F58202BFC4D0CC6680BE7DD9F5CA30AA2BB5D1998145DE33D54101B80E2CA49FAF918
          09                                # unsigned(9)
          58 3C                             # bytes(60)
             8613A1157832687474703A2F2F6578616D706C652E636F6D2F766572792F6C6F6E672F706174682F746F2F66696C652F66696C652E62696E1502030F
          0D                                # unsigned(13)
          59 0204                           # bytes(516)
             A20179019D2323204578616D706C6520323A2053696D756C74616E656F757320446F776E6C6F61642C20496E7374616C6C6174696F6E2C2053656375726520426F6F742C2053657665726564204669656C64730A0A2020202054686973206578616D706C6520636F766572732074686520666F6C6C6F77696E672074656D706C617465733A0A202020200A202020202A20436F6D7061746962696C69747920436865636B20287B7B74656D706C6174652D636F6D7061746962696C6974792D636865636B7D7D290A202020202A2053656375726520426F6F7420287B7B74656D706C6174652D7365637572652D626F6F747D7D290A202020202A204669726D7761726520446F776E6C6F616420287B7B6669726D776172652D646F776E6C6F61642D74656D706C6174657D7D290A202020200A2020202054686973206578616D706C6520616C736F2064656D6F6E7374726174657320736576657261626C6520656C656D656E747320287B7B6F76722D736576657261626C657D7D292C20616E64207465787420287B7B6D616E69666573742D6469676573742D746578747D7D292E814100A2036761726D2E636F6D0578525468697320636F6D706F6E656E7420697320612064656D6F6E7374726174696F6E2E205468652064696765737420697320612073616D706C65207061747465726E2C206E6F742061207265616C206F6E652E


## CBOR Binary (extracted)
    D8 6B                                      # tag(107) / SUIT_Envelope /
       A4                                      # map(4)
          02                                   # unsigned(2) / authentication-wrapper : /
          58 98                                # bytes(152)
             # SUIT_Authentication #
             82                                # array(2)
                58 24                          # bytes(36)
                   # SUIT_Digest #
                   82                          # array(2)
                      2F                       # negative(15) / algorithm-id : sha256 /
                      58 20                    # bytes(32)
                         E45DCDB2074B951F1C88B866469939C2A83ED433A31FC7DFCB3F63955BD943EC
                58 4A                          # bytes(74)
                   # SUIT_Authentication_Block #
                   D2                          # tag(18) / COSE_Sign1 /
                      84                       # array(4)
                         43                    # bytes(3)
                            # protected #
                            A1                 # map(1)
                               01              # unsigned(1) / alg : /
                               26              # negative(6) / -7 /
                         A0                    # map(0)
                         F6                    # primitive(22) / null /
                         58 40                 # bytes(64) / signature : /
                            B4FD3A6A18FE1062573488CF24AC96EF9F30AC746696E50BE96533B356B8156E4332587FE6F4E8743AE525D72005FDDD4C1213D55A8061B2CE67B83640F4777C
          03                                   # unsigned(3) / manifest : /
          58 BB                                # bytes(187)
             # SUIT_Manifest #
             A7                                # map(7)
                01                             # unsigned(1) / manifest-version : /
                01                             # unsigned(1)
                02                             # unsigned(2) / manifest-sequence-number : /
                02                             # unsigned(2)
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
                               0E              # unsigned(14) / image-size : /
                               19 87D0         # unsigned(34768)
                            01                 # unsigned(1)  / condition-vendor-identifier : /
                            0F                 # unsigned(15)
                            02                 # unsigned(2)  / condition-class-identifier : /
                            0F                 # unsigned(15)
                09                             # unsigned(9)  / install : /
                82                             # array(2)
                   2F                          # negative(15) / algorithm-id : sha256 /
                   58 20                       # bytes(32)    / digest-bytes : /
                      3EE96DC79641970AE46B929CCF0B72BA9536DD846020DBDC9F949D84EA0E18D2
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
                0D                             # unsigned(13) / text : /
                82                             # array(2)
                   2F                          # negative(15) / algorithm-id : sha256 /
                   58 20                       # bytes(32)    / digest-bytes : /
                      2BFC4D0CC6680BE7DD9F5CA30AA2BB5D1998145DE33D54101B80E2CA49FAF918
          09                                   # unsigned(9)  / install : /
          58 3C                                # bytes(60)
             # SUIT_Command_Sequence #
             86                                # array(6)
                13                             # unsigned(19) / directive-set-parameters : /
                A1                             # map(1)
                   15                          # unsigned(21) / uri : /
                   78 32                       # text(50)  / "http://example.com/very/long/path/to/file/file.bin" /
                      687474703A2F2F6578616D706C652E636F6D2F766572792F6C6F6E672F706174682F746F2F66696C652F66696C652E62696E
                15                             # unsigned(21) / directive-fetch : /
                02                             # unsigned(2)
                03                             # unsigned(3)  / condition-image-match : /
                0F                             # unsigned(15)
          0D                                   # unsigned(13) / text : /
          59 0204                              # bytes(516)
             # SUIT_Text_Map #
             A2                                # map(2)
                01                             # unsigned(1) / text-manifest-description : /
                79 019D                        # text(413) / "## Example 2: Simul"... /
                   2323204578616D706C6520323A2053696D756C74616E656F757320446F776E6C6F61642C20496E7374616C6C6174696F6E2C2053656375726520426F6F742C2053657665726564204669656C64730A0A2020202054686973206578616D706C6520636F766572732074686520666F6C6C6F77696E672074656D706C617465733A0A202020200A202020202A20436F6D7061746962696C69747920436865636B20287B7B74656D706C6174652D636F6D7061746962696C6974792D636865636B7D7D290A202020202A2053656375726520426F6F7420287B7B74656D706C6174652D7365637572652D626F6F747D7D290A202020202A204669726D7761726520446F776E6C6F616420287B7B6669726D776172652D646F776E6C6F61642D74656D706C6174657D7D290A202020200A2020202054686973206578616D706C6520616C736F2064656D6F6E7374726174657320736576657261626C6520656C656D656E747320287B7B6F76722D736576657261626C657D7D292C20616E64207465787420287B7B6D616E69666573742D6469676573742D746578747D7D292E
                81                             # array(1)  / [[h'00']] /
                   41                          # bytes(1)
                      00                       # "\x00"
                A2                             # map(2)
                   03                          # unsigned(3) / vendor-domain : /
                   67                          # text(7)   / "arm.com" /
                      61726D2E636F6D
                   05                          # unsigned(5) / component-description : /
                   78 52                       # text(82)  / "This component is a demonstration."... /
                      5468697320636F6D706F6E656E7420697320612064656D6F6E7374726174696F6E2E205468652064696765737420697320612073616D706C65207061747465726E2C206E6F742061207265616C206F6E652E


## Command
    echo -en "\xD8\x6B\xA4\x02\x58\x73\x82\x58\x24\x82\x2F\x58\x20\xE4\x5D\xCD\xB2\x07\x4B\x95\x1F\x1C\x88\xB8\x66\x46\x99\x39\xC2\xA8\x3E\xD4\x33\xA3\x1F\xC7\xDF\xCB\x3F\x63\x95\x5B\xD9\x43\xEC\x58\x4A\xD2\x84\x43\xA1\x01\x26\xA0\xF6\x58\x40\xB4\xFD\x3A\x6A\x18\xFE\x10\x62\x57\x34\x88\xCF\x24\xAC\x96\xEF\x9F\x30\xAC\x74\x66\x96\xE5\x0B\xE9\x65\x33\xB3\x56\xB8\x15\x6E\x43\x32\x58\x7F\xE6\xF4\xE8\x74\x3A\xE5\x25\xD7\x20\x05\xFD\xDD\x4C\x12\x13\xD5\x5A\x80\x61\xB2\xCE\x67\xB8\x36\x40\xF4\x77\x7C\x03\x58\xBB\xA7\x01\x01\x02\x02\x03\x58\x5F\xA2\x02\x81\x81\x41\x00\x04\x58\x56\x86\x14\xA4\x01\x50\xFA\x6B\x4A\x53\xD5\xAD\x5F\xDF\xBE\x9D\xE6\x63\xE4\xD4\x1F\xFE\x02\x50\x14\x92\xAF\x14\x25\x69\x5E\x48\xBF\x42\x9B\x2D\x51\xF2\xAB\x45\x03\x58\x24\x82\x2F\x58\x20\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x0E\x19\x87\xD0\x01\x0F\x02\x0F\x09\x82\x2F\x58\x20\x3E\xE9\x6D\xC7\x96\x41\x97\x0A\xE4\x6B\x92\x9C\xCF\x0B\x72\xBA\x95\x36\xDD\x84\x60\x20\xDB\xDC\x9F\x94\x9D\x84\xEA\x0E\x18\xD2\x0A\x43\x82\x03\x0F\x0C\x43\x82\x17\x02\x0D\x82\x2F\x58\x20\x2B\xFC\x4D\x0C\xC6\x68\x0B\xE7\xDD\x9F\x5C\xA3\x0A\xA2\xBB\x5D\x19\x98\x14\x5D\xE3\x3D\x54\x10\x1B\x80\xE2\xCA\x49\xFA\xF9\x18\x09\x58\x3C\x86\x13\xA1\x15\x78\x32\x68\x74\x74\x70\x3A\x2F\x2F\x65\x78\x61\x6D\x70\x6C\x65\x2E\x63\x6F\x6D\x2F\x76\x65\x72\x79\x2F\x6C\x6F\x6E\x67\x2F\x70\x61\x74\x68\x2F\x74\x6F\x2F\x66\x69\x6C\x65\x2F\x66\x69\x6C\x65\x2E\x62\x69\x6E\x15\x02\x03\x0F\x0D\x59\x02\x04\xA2\x01\x79\x01\x9D\x23\x23\x20\x45\x78\x61\x6D\x70\x6C\x65\x20\x32\x3A\x20\x53\x69\x6D\x75\x6C\x74\x61\x6E\x65\x6F\x75\x73\x20\x44\x6F\x77\x6E\x6C\x6F\x61\x64\x2C\x20\x49\x6E\x73\x74\x61\x6C\x6C\x61\x74\x69\x6F\x6E\x2C\x20\x53\x65\x63\x75\x72\x65\x20\x42\x6F\x6F\x74\x2C\x20\x53\x65\x76\x65\x72\x65\x64\x20\x46\x69\x65\x6C\x64\x73\x0A\x0A\x20\x20\x20\x20\x54\x68\x69\x73\x20\x65\x78\x61\x6D\x70\x6C\x65\x20\x63\x6F\x76\x65\x72\x73\x20\x74\x68\x65\x20\x66\x6F\x6C\x6C\x6F\x77\x69\x6E\x67\x20\x74\x65\x6D\x70\x6C\x61\x74\x65\x73\x3A\x0A\x20\x20\x20\x20\x0A\x20\x20\x20\x20\x2A\x20\x43\x6F\x6D\x70\x61\x74\x69\x62\x69\x6C\x69\x74\x79\x20\x43\x68\x65\x63\x6B\x20\x28\x7B\x7B\x74\x65\x6D\x70\x6C\x61\x74\x65\x2D\x63\x6F\x6D\x70\x61\x74\x69\x62\x69\x6C\x69\x74\x79\x2D\x63\x68\x65\x63\x6B\x7D\x7D\x29\x0A\x20\x20\x20\x20\x2A\x20\x53\x65\x63\x75\x72\x65\x20\x42\x6F\x6F\x74\x20\x28\x7B\x7B\x74\x65\x6D\x70\x6C\x61\x74\x65\x2D\x73\x65\x63\x75\x72\x65\x2D\x62\x6F\x6F\x74\x7D\x7D\x29\x0A\x20\x20\x20\x20\x2A\x20\x46\x69\x72\x6D\x77\x61\x72\x65\x20\x44\x6F\x77\x6E\x6C\x6F\x61\x64\x20\x28\x7B\x7B\x66\x69\x72\x6D\x77\x61\x72\x65\x2D\x64\x6F\x77\x6E\x6C\x6F\x61\x64\x2D\x74\x65\x6D\x70\x6C\x61\x74\x65\x7D\x7D\x29\x0A\x20\x20\x20\x20\x0A\x20\x20\x20\x20\x54\x68\x69\x73\x20\x65\x78\x61\x6D\x70\x6C\x65\x20\x61\x6C\x73\x6F\x20\x64\x65\x6D\x6F\x6E\x73\x74\x72\x61\x74\x65\x73\x20\x73\x65\x76\x65\x72\x61\x62\x6C\x65\x20\x65\x6C\x65\x6D\x65\x6E\x74\x73\x20\x28\x7B\x7B\x6F\x76\x72\x2D\x73\x65\x76\x65\x72\x61\x62\x6C\x65\x7D\x7D\x29\x2C\x20\x61\x6E\x64\x20\x74\x65\x78\x74\x20\x28\x7B\x7B\x6D\x61\x6E\x69\x66\x65\x73\x74\x2D\x64\x69\x67\x65\x73\x74\x2D\x74\x65\x78\x74\x7D\x7D\x29\x2E\x81\x41\x00\xA2\x03\x67\x61\x72\x6D\x2E\x63\x6F\x6D\x05\x78\x52\x54\x68\x69\x73\x20\x63\x6F\x6D\x70\x6F\x6E\x65\x6E\x74\x20\x69\x73\x20\x61\x20\x64\x65\x6D\x6F\x6E\x73\x74\x72\x61\x74\x69\x6F\x6E\x2E\x20\x54\x68\x65\x20\x64\x69\x67\x65\x73\x74\x20\x69\x73\x20\x61\x20\x73\x61\x6D\x70\x6C\x65\x20\x70\x61\x74\x74\x65\x72\x6E\x2C\x20\x6E\x6F\x74\x20\x61\x20\x72\x65\x61\x6C\x20\x6F\x6E\x65\x2E" > suit_manifest_exp2.cbor
