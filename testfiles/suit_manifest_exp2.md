<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    B.3.  Example 2: Simultaneous Download, Installation, Secure Boot, Severed Fields
    https://tools.ietf.org/html/draft-ietf-suit-manifest-18#appendix-B.3


## CBOR Diagnostic
    / SUIT_Envelope = /
    107({
        / authentication-wrapper / 2: << [
            / digest: / << [
                / algorithm-id: / -16 / sha256 /,
                / digest-bytes: / h'a85153c05f709e681877ee23c0de3e2f92bcc66c1ad6f41b39157ac7cb6a5a62'
            ] >>,
            / signature: / << 18([
                / protected: / << {
                    / alg / 1: -7 / ES256 /,
                } >>,
                / unprotected: / {
                },
                / payload: / nil,
                / signature: / h'4ba6e9c4bdd65212e2e4775b7f5bb32faf14209f88d9f8b198e21c338770aa542dde07e31fa17ca9dadee4d94c43dfba81819d3588d7fde5eff010b8c7c89277'
            ]) >>
        ] >>,
        / manifest / 3: << {
            / manifest-version / 1: 1,
            / manifest-sequence-number / 2: 2,
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
            ] >>,
            / install / 17: << [
                / algorithm-id: / -16 / sha256 /,
                / digest-bytes: / h'3ee96dc79641970ae46b929ccf0b72ba9536dd846020dbdc9f949d84ea0e18d2'
            ] >>,
            / text / 23: << [
                / algorithm-id / -16 / sha256 /,
                / digest-bytes / h'2bfc4d0cc6680be7dd9f5ca30aa2bb5d1998145de33d54101b80e2ca49faf918'
            ] >>
        } >>,
        / install / 17: << [
            / directive-set-parameters / 19, {
              / uri / 21: 'http://example.com/very/long/path/to/file/file.bin',
            },
            / directive-fetch / 21, 2,
            / condition-image-match / 3, 15
        ] >>,
        / text / 23: << {
            [h'00']: {
                / vendor-domain / 3: 'arm.com',
                / component-description / 5: 'This component is a demonstration. The digest is a sample pattern, not a real one.'
            }
        } >>
    })
