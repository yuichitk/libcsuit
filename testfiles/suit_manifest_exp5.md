<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    B.6.  Example 5: Two Images
    https://tools.ietf.org/html/draft-ietf-suit-manifest-18#appendix-B.6


## CBOR Diagnostic
    / SUIT_Envelope = /
    107({
        / authentication-wrapper / 2: << [
            / digest: / << [
                / algorithm-id: / -16 / sha256 /,
                / digest-bytes: / h'a4c6d5f5c3800c19c4af55aacc1c2dc6e37e2bf10b2aab335f70226961e310d3'
            ] >>,
            / signatures: / << 18([
                / protected: / << {
                    / alg / 1:-7 / ES256 /,
                } >>,
                / unprotected: / {
                },
                / payload: / nil,
                / signature: / h'91d95d3bb2eaae7b31ff11f4761056e491bcb07470119f9c69388982c3238eabfcb477ec7887f36c31e7d957fe8830b3ae8b9d7d71372de2e71a9a3b67444c4a'
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
                            / algorithm-id: / -16 / sha256 /,
                            / digest-bytes: / h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
                        ] >>,
                        / image-size / 14: 34768
                    },
                    / condition-vendor-identifier / 1, 15,
                    / condition-class-identifier / 2, 15,
                    / directive-set-component-index / 12, 1,
                    / directive-override-parameters / 20, {
                        / image-digest / 3: << [
                            / algorithm-id: / -16 / sha256 /,
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
                / directive-set-parameters / 19, {
                    / uri / 21: 'http://example.com/file1.bin'
                },
                / directive-fetch / 21, 2,
                / condition-image-match / 3, 15,
                / directive-set-component-index / 12, 1,
                / directive-set-parameters / 19, {
                    / uri / 21: 'http://example.com/file2.bin'
                },
                / directive-fetch / 21, 2,
                / condition-image-match / 3, 15
            ] >>
        } >>
    })
