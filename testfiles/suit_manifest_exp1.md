<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    B.2.  Example 1: Simultaneous Download and Installation of Payload
    https://tools.ietf.org/html/draft-ietf-suit-manifest-18#appendix-B.2


## CBOR Diagnostic
    / SUIT_Envelope = /
    107({
        / authentication-wrapper / 2: << [
            / digest: / << [
                / algorithm-id: / -16 / sha256 /,
                / digest-bytes: / h'176653ec03837a8d32b1eb0b91ea5e8a2256bc2e7c02e5bb7f45f431fa926f3e'
            ] >>,
            / signature: / << 18([
                / protected: / << {
                    / alg / 1: -7 / ES256 /,
                } >>,
                / unprotected: / {
                },
                / payload: / nil,
                / signature: / h'a78dbd584dbdea66ab024179dac2f4b244940e9dfe1337bb833e3e3df2562a0fceb77e64980e0ddcc24b8abb63b78aad9ad42fd244b684dd39859f84740239e8'
            ]) >>
        ] >>,
        / manifest / 3: << {
            / manifest-version / 1: 1,
            / manifest-sequence-number / 2: 1,
            / common / 3: << {
                / components / 2: [
                    [h'00']
                ],
                / common-sequence / 4: << [
                    / directive-override-parameters / 20, {
                        / vendor-id / 1: h'fa6b4a53d5ad5fdfbe9de663e4d41ffe' / fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe /,
                        / class-id / 2: h'1492af1425695e48bf429b2d51f2ab45' / 1492af14-2569-5e48-bf42-9b2d51f2ab45 /,
                        / image-digest / 3: << [
                            / algorithm-id: / -16 / sha256 /,
                            / digest-bytes: / h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
                        ] >>,
                        / image-size / 14: 34768,
                    },
                    / condition-vendor-identifier / 1, 15,
                    / condition-class-identifier / 2, 15
                ] >>,
            } >>,
            / validate / 7: << [
                / condition-image-match / 3, 15
            ] >>,
            / install / 17: << [
                / directive-set-parameters / 19, {
                    / uri / 21: 'http://example.com/file.bin',
                },
                / directive-fetch / 21, 2,
                / condition-image-match / 3, 15
            ] >>
        } >>
    })
