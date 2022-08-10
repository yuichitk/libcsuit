<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    B.4.  Example 3: A/B images
    https://tools.ietf.org/html/draft-ietf-suit-manifest-19#appendix-B.4


## CBOR Diagnostic
    / SUIT_Envelope = /
    107({
        / authentication-wrapper / 2: << [
            / digest: / << [
                / algorithm-id: / -16 / SHA-256 /,
                / digest-bytes: / h'b3e6a52776bf3ed218feba031c609c98260e1a52fc1f019683edb6d1c5c4a379'
            ] >>,
            / signatures: / << 18([
                / protected: / << {
                    / alg / 1: -7 / ES256 /
                } >>,
                / unprotected: / {
                },
                / payload: / null,
                / signature: / h'9ff1d63474897d302f7ec4ab98cb07e22c9853b92a56e3ec9286a4e248d4ac59665de35824c1caad4b056b35e8a40c60086f36eb519e31c7710db4fdc0b99eff'
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
                                / component-slot / 5: 0
                            },
                            / condition-component-slot / 5, 5,
                            / directive-override-parameters / 20, {
                                / image-digest / 3: << [
                                    / algorithm-id: / -16 / SHA-256 /,
                                    / digest-bytes: / h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
                                ] >>,
                                / image-size / 14: 34768
                            }
                        ] >>,
                        << [
                            / directive-override-parameters / 20, {
                                / component-slot / 5: 1
                            },
                            / condition-component-slot / 5, 5,
                            / directive-override-parameters / 20, {
                                / image-digest / 3: << [
                                    / algorithm-id: / -16 / SHA-256 /,
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
                        / directive-override-parameters / 20, {
                            / component-slot / 5: 0
                        },
                        / condition-component-slot / 5, 5,
                        / directive-override-parameters / 20, {
                            / uri / 21: "http://example.com/file1.bin"
                        }
                    ] >>,
                    << [
                        / directive-override-parameters / 20, {
                            / component-slot / 5: 1
                        },
                        / condition-component-slot / 5, 5,
                        / directive-override-parameters / 20, {
                            / uri / 21: "http://example.com/file2.bin"
                        }
                    ] >>
                ],
                / directive-fetch / 21, 2,
                / condition-image-match / 3, 15
            ] >>
        } >>
    })
