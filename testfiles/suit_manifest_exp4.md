<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    B.5.  Example 4: Load and Decompress from External Storage
    https://tools.ietf.org/html/draft-ietf-suit-manifest-18#appendix-B.5


## CBOR Diagnostic
    / SUIT_Envelope = /
    107({
        / authentication-wrapper / 2: << [
            / digest: / << [
                / algorithm-id: / -16 / sha256 /,
                / digest-bytes: / h'601ebc1bb2e12cbaf408b1bca72fae0d9987498acfa16130ce4cf5cc9ea74c7c'
            ] >>,
            / signature: / << 18([
                / protected: / << {
                    / alg / 1:-7 / ES256 /,
                } >>,
                / unprotected: / {
                },
                / payload: / nil,
                / signature: / h'2e263599b0f3613fd3feb0cec1ff55c6b37c521339ef2680dc63de3a5cdfb0e3f44237313e1c17c35f7fa84af82234f50cea551cfdd8179a40dac5136167cd5e'
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
                            / algorithm-id: / -16 / sha256 /,
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
                / directive-set-parameters / 19, {
                    / image-digest / 3: << [
                        / algorithm-id: / -16 / sha256 /,
                        / digest-bytes: / h'0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff'
                    ] >>,
                    / image-size / 14: 76834,
                    / source-component / 22: 0 / [h'00'] /,
                    / compression-info / 19, << {
                        / compression-algorithm / 1: 1 / "zlib" /
                    } >>
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
                / directive-set-parameters / 19, {
                    / uri / 21: 'http://example.com/file.bin',
                } ,
                / directive-fetch / 21, 2 ,
                / condition-image-match / 3, 15
            ] >>,
            / install / 17: << [
                / directive-set-component-index / 12, 0,
                / directive-set-parameters / 19, {
                    / source-component / 22: 1 / [h'02'] /,
                },
                / directive-copy / 22, 2,
                / condition-image-match / 3, 15
            ] >>
        } >>
    })
