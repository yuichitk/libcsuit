<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    B.5.  Example 4: Load and Decompress from External Storage
    https://tools.ietf.org/html/draft-ietf-suit-manifest-19#appendix-B.5


## CBOR Diagnostic
    / SUIT_Envelope = /
    107({
        / authentication-wrapper / 2: << [
            / digest: / << [
                / algorithm-id: / -16 / SHA-256 /,
                / digest-bytes: / h'838eb848698c9d9dd29b5930102ea1f29743857d975f52ed4d19589b821e82cf'
            ] >>,
            / signatures: / << 18([
                / protected: / << {
                    / alg / 1: -7 / ES256 /
                } >>,
                / unprotected: / {
                },
                / payload: / null,
                / signature: / h'5ee9d2698734cef75582a2c188a328b06d414b20dff7043528045a3fc2bdcb6be36887e2dfdb6ea5ab91d74077a6cc806c4580026bfea22c4f3153e1d9692c5a'
            ]) >>
        ] >>,
        / manifest / 3: << {
            / manifest-version / 1: 1,
            / manifest-sequence-number / 2: 4,
            / common / 3: << {
                / components / 2: [
                    [h'00'],
                    [h'02'],
                    [h'01']
                ],
                / common-sequence / 4: << [
                    / directive-set-component-index / 12, 0,
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
                / directive-set-component-index / 12, 0,
                / condition-image-match / 3, 15
            ] >>,
            / load / 8: << [
                / directive-set-component-index / 12, 2,
                / directive-override-parameters / 20, {
                    / image-digest / 3: << [
                        / algorithm-id: / -16 / SHA-256 /,
                        / digest-bytes: / h'0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff'
                    ] >>,
                    / image-size / 14: 76834,
                    / source-component / 22: 0
                },
                / directive-copy / 22, 2,
                / condition-image-match / 3, 15
            ] >>,
            / run / 9: << [
                / directive-set-component-index / 12, 2,
                / directive-run / 23, 2
            ] >>,
            / payload-fetch / 16: << [
                / directive-set-component-index / 12, 1,
                / directive-override-parameters / 20, {
                    / image-digest / 3: << [
                        / algorithm-id: / -16 / SHA-256 /,
                        / digest-bytes: / h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
                    ] >>,
                    / uri / 21: "http://example.com/file.bin"
                },
                / directive-fetch / 21, 2,
                / condition-image-match / 3, 15
            ] >>,
            / install / 17: << [
                / directive-set-component-index / 12, 0,
                / directive-override-parameters / 20, {
                    / source-component / 22: 1
                },
                / directive-copy / 22, 2,
                / condition-image-match / 3, 15
            ] >>
        } >>
    })
