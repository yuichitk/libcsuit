<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    B.1.  Example 0: Firmware Encryption
    https://tools.ietf.org/html/draft-ietf-suit-firmware-encryption#appendix-B.1


## CBOR Diagnostic
    / SUIT_Envelope = /
    107({
        / authentication-wrapper / 2: << [
            / digest: / << [
                / algorithm-id / -16 / sha256 /,
                / digest-bytes / h'efab0366d4336cc65a8f59022a6d67b7a11eea699b20c827f7688e82f49252b9'
            ] >>,
            / signature: / << 18([
                / protected / << {
                    / alg / 1: -7 / ES256 /
                } >>,
                / unprotected / {
                },
                / payload / nil,
                / signature / h'ca7f12cb7cf943e91972a0a1a79965c37c6ea823cde791a7d2018705aa9e19a2688008a6866d5664eaa1658bf5d2f84e6a24f78fa1195d8afb07f552077937ad'
            ]) >>
        ] >>,
        / integrated-payload / "#encrypted-firmware": h'4a229f5c3be5bf7b723c783589a6225c2cd1c0afb8d50b9c406764d684e38cd4595f526cebfbff119ce4',
        / manifest / 3: << {
            / manifest-version / 1: 1,
            / manifest-sequence-number / 2: 0,
            / common / 3: << {
                / components / 2: [
                    [ h'00' ],
                    [ h'01' ]
                ],
                / common-sequence / 4: << [
                    / directive-set-component-index / 12, 0,
                    / directive-override-parameters / 20, {
                        / vendor-id / 1: h'c0ddd5f15243566087db4f5b0aa26c2f',
                        / class-id / 2: h'db42f7093d8c55baa8c5265fc5820f4e',
                        / image-digest / 3: << [
                            / algorithm-id: / -16 / sha256 /,
                            / digest-bytes: / h'b34fbe453916f9e12dc6701393b241d4841be4d80d2f5164bccd5205bc8275af'
                        ] >>,
                        / image-size / 14: 42
                    },
                    / condition-vendor-identifier / 1, 15,
                    / condition-class-identifier / 2, 15
                ] >>
            },
            / install / 17: << [
                / directive-set-component-index / 12, 1,
                / directive-override-parameters / 20, {
                    / uri / 21: "#encrypted-firmware"
                },
                / directive-fetch / 21, 15,
                / condition-image-match / 3, 15
            ] >>,
            / validate / 7: << [
                / directive-set-component-index / 12, 0,
                / condition-image-match / 3, 15
            ] >>,
            / load / 8: << [
                / directive-set-component-index/ 12, 0,
                / directive-override-parameters / 20, {
                    / image-digest / 3: << [
                        / algorithm-id: / -16,
                        / digest-bytes: / h'36921488fe6680712f734e11f58d87eeb66d4b21a8a1ad3441060814da16d50f'
                    ] >>,
                    / image-size / 14: 30,
                    / source-component / 22: 1, / [h'01'] /
                    / encryption-info / 18: << 96([
                        / protected: / << {
                            / alg / 1: 1 / AES-GCM-128 /
                        } >>,
                        / unprotected: / {
                            / iv / 5: h'e016c28ff8350ef0ad9ad0028535ef01'
                        },
                        / payload: / nil,
                        / recipients: / [ / XXX: not array of COSE_recipient /
                            / protected: / << {
                                / alg / 1: -100 / HPKE-AES-128-GCM /
                            } >>,
                            / unprotected: / {
                                -1: << {
                                    / kty / 1: 2 / EC2 /,
                                    / crv / -1: 1 / P-256 /,
                                    / x-coordinate / -2: h'e98086d070841a55dc4ca29ed73986bd4d8af45f0aa55af922e62112e73dd051',
                                    / y-coordinate / -3: h'c72bef9dd5f388a90f9f02df484f7ed8174497ac6e83042c240848483b7fa8d0'
                                } >>,
                                / kid / 4: h'6b69642d32' / "kid-2" /
                            },
                            / encrypted CEK: / h'3742f84b10a6e56be92fdbeef2650d2a63617da412f2a7a7e8e7827fc046fa50'
                        ]
                    ]) >>
                },
                / directive-copy / 22, 2,
                / condition-image-match / 3, 15
            ] >>
        } >>
    })


## CBOR binary
    D8 6B                                   # tag(107)
       A3                                   # map(3)
          02                                # unsigned(2)
          58 73                             # bytes(115)
             825824822F5820EFAB0366D4336CC65A8F59022A6D67B7A11EEA699B20C827F7688E82F49252B9584AD28443A10126A0F65840CA7F12CB7CF943E91972A0A1A79965C37C6EA823CDE791A7D2018705AA9E19A2688008A6866D5664EAA1658BF5D2F84E6A24F78FA1195D8AFB07F552077937AD
          73                                # text(19)
             23656E637279707465642D6669726D77617265 # "#encrypted-firmware"
          58 2A                             # bytes(42)
             4A229F5C3BE5BF7B723C783589A6225C2CD1C0AFB8D50B9C406764D684E38CD4595F526CEBFBFF119CE4
          03                                # unsigned(3)
          59 0167                           # bytes(359)
             A601010200035863A20282814100814101045857880C0014A40150C0DDD5F15243566087DB4F5B0AA26C2F0250DB42F7093D8C55BAA8C5265FC5820F4E035824822F5820B34FBE453916F9E12DC6701393B241D4841BE4D80D2F5164BCCD5205BC8275AF0E182A010F020F11581E880C0114A1157323656E637279707465642D6669726D77617265150F030F0745840C00030F0858D1880C0014A4035824822F582036921488FE6680712F734E11F58D87EEB66D4B21A8A1AD3441060814DA16D50F0E181E1601125899D8608443A10101A10550E016C28FF8350EF0AD9AD0028535EF01F68344A1013863A220584BA401022001215820E98086D070841A55DC4CA29ED73986BD4D8AF45F0AA55AF922E62112E73DD051225820C72BEF9DD5F388A90F9F02DF484F7ED8174497AC6E83042C240848483B7FA8D004456B69642D3258203742F84B10A6E56BE92FDBEEF2650D2A63617DA412F2A7A7E8E7827FC046FA501602030F
