<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    B.6.  Example 5: Two Images
    https://tools.ietf.org/html/draft-ietf-suit-manifest-19#appendix-B.6


## CBOR Diagnostic
    / SUIT_Envelope = /
    107({
        / authentication-wrapper / 2: << [
            / digest: / << [
                / algorithm-id: / -16 / SHA-256 /,
                / digest-bytes: / h'264dc89eb4a39ae7a8ed05e4d6232153bce4fb9a111a31310b90627d1edfc3bb'
            ] >>,
            / signatures: / << 18([
                / protected: / << {
                    / alg / 1: -7 / ES256 /
                } >>,
                / unprotected: / {
                },
                / payload: / null,
                / signature: / h'c0bf1b20b847292dc45015a013edbc56915b22fe81a8aec825eac2fb3b084fa6fa08761461987c92189ec6b8b5ab361d2588b05070b3ed03943549bafd355bf0'
            ]) >>
        ] >>,
        / manifest / 3: << {
            / manifest-version / 1: 1,
            / manifest-sequence-number / 2: 5,
            / common / 3: << {
                / components / 2: [
                    [h'00'],
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
                    / condition-class-identifier / 2, 15,
                    / directive-set-component-index / 12, 1,
                    / directive-override-parameters / 20, {
                        / image-digest / 3: << [
                            / algorithm-id: / -16 / SHA-256 /,
                            / digest-bytes: / h'0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff'
                        ] >>,
                        / image-size / 14: 76834
                    }
                ] >>
            } >>,
            / validate / 7: << [
                / directive-set-component-index / 12, 0,
                / condition-image-match / 3, 15,
                / directive-set-component-index / 12, 1,
                / condition-image-match / 3, 15
            ] >>,
            / run / 9: << [
                / directive-set-component-index / 12, 0,
                / directive-run / 23, 2
            ] >>,
            / install / 17: << [
                / directive-set-component-index / 12, 0,
                / directive-override-parameters / 20, {
                    / uri / 21: "http://example.com/file1.bin"
                },
                / directive-fetch / 21, 2,
                / condition-image-match / 3, 15,
                / directive-set-component-index / 12, 1,
                / directive-override-parameters / 20, {
                    / uri / 21: "http://example.com/file2.bin"
                },
                / directive-fetch / 21, 2,
                / condition-image-match / 3, 15
            ] >>
        } >>
    })
