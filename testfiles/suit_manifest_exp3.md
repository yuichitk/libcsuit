<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    B.4.  Example 3: A/B images
    https://tools.ietf.org/html/draft-ietf-suit-manifest-18#appendix-B.4


## CBOR Diagnostic
    / SUIT_Envelope = /
    107({
        / authentication-wrapper / 2: << [
            / digest: / << [
                / algorithm-id: / -16 / sha256 /,
                / digest-bytes: / h'c98d9240343ee1ac12ba833c04fb9006e70f62c7e4c36edb0b2a356d59c2f86c'
            ] >>,
            / signature: / << 18([
                / protected: / << {
                    / alg / 1: -7 / ES256 /
                } >>,
                / unprotected: / {
                },
                / payload: / null,
                / signature: / h'451b3099c7914ef4c54b633688471b8d0f940d09eeca41c159927a9f044bddec536f83da5f1b1047bc415be013d71524ad82e4ac792a61f93dbdc875a7a6adeb'
            ]) >>
        ] >>,
        / manifest / 3: << {
            / manifest-version / 1: 1,
            / manifest-sequence-number / 2: 3,
            / common / 3: << {
                / components / 2: [
                     [h'00']
                ],
                / common-sequence / 4: << [
                    / directive-override-parameters / 20, {
                        / vendor-id / 1: h'fa6b4a53d5ad5fdfbe9de663e4d41ffe' / fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe /,
                        / class-id / 2: h'1492af1425695e48bf429b2d51f2ab45' / 1492af14-2569-5e48-bf42-9b2d51f2ab45 /
                    },
                    / directive-try-each / 15, [
                        << [
                            / directive-override-parameters / 20, {
                                / offset / 5: 33792
                            },
                            / condition-component-slot / 5, 5,
                            / directive-override-parameters / 20, {
                                / image-digest / 3: << [
                                    / algorithm-id: / -16 / sha256 /,
                                    / digest-bytes: / h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
                                ] >>,
                                / image-size / 14: 34768
                            }
                        ] >>,
                        << [
                            / directive-override-parameters / 20, {
                                / offset / 5: 541696
                            },
                            / condition-component-slot / 5, 5,
                            / directive-override-parameters / 20, {
                                / image-digest: / 3: << [
                                    / algorithm-id: / -16 / sha256 /,
                                    / digest-bytes: / h'0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff'
                                ] >>,
                                / image-size / 14: 76834
                            }
                        ] >>
                    ],
                    / condition-vendor-identifier / 1, 15,
                    / condition-class-identifier / 2, 15
                ] >>
            } >>,
            / validate / 7: << [
                / condition-image-match / 3, 15
            ] >>,
            / install / 17: << [
                / directive-try-each / 15, [
                    << [
                        / directive-set-parameters / 19, {
                            / offset / 5: 33792
                        },
                        / condition-component-slot / 5, 5,
                        / directive-set-parameters / 19, {
                            / uri / 21: "http://example.com/file1.bin"
                        }
                    ] >>,
                    << [
                        / directive-set-parameters / 19, {
                            / offset / 5:541696
                        },
                        / condition-component-slot / 5, 5,
                        / directive-set-parameters / 19, {
                            / uri / 21: "http://example.com/file2.bin"
                        }
                    ] >>
                ],
                / directive-fetch / 21, 2,
                / condition-image-match / 3, 15
            ] >>
        } >>
    })
