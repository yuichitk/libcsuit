<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    B.1.  Example 0: Secure Boot
    https://tools.ietf.org/html/draft-ietf-suit-manifest-19#appendix-B.1


## CBOR Diagnostic
    / SUIT_Envelope = /
    107({
        / authentication-wrapper / 2: << [
            / digest: / << [
                / algorithm-id: / -16 / SHA-256 /,
                / digest-bytes: / h'6658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af'
            ] >>,
            / signatures: / << 18([
                / protected: / << {
                    / alg / 1: -7 / ES256 /
                } >>,
                / unprotected: / {
                },
                / payload: / null,
                / signature: / h'68113f1e76731330fea16136cead2be4fa8d4bb3e327e3f9232eb4f13b5d118f2ea6e31d9a09a240f6f5770776916e15a4ebca1b6262cf6e40a44353bd8161d9'
            ]) >>
        ] >>,
        / manifest / 3: << {
            / manifest-version / 1: 1,
            / manifest-sequence-number / 2: 0,
            / common / 3: << {
                / components / 2: [
                    [h'00']
                ],
                / common-sequence / 4: << [
                    / directive-override-parameters / 20, {
                        / vendor-id / 1: h'fa6b4a53d5ad5fdfbe9de663e4d41ffe' / fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe /,
                        / class-id / 2: h'1492af1425695e48bf429b2d51f2ab45' / 1492af14-2569-5e48-bf42-9b2d51f2ab45 /,
                        / image-digest / 3: << [
                            / algorithm-id: / -16 / SHA-256 /,
                            / digest-bytes: / h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
                        ] >>,
                        / image-size / 14: 34768
                    },
                    / condition-vendor-identifier / 1, 15,
                    / condition-class-identifier / 2, 15
                ] >>
            } >>,
            / validate / 7: << [
                / condition-image-match / 3, 15
            ] >>,
            / run / 9: << [
                / directive-run / 23, 2
            ] >>
        } >>
    })
