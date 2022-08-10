<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    B.3.  Example 2: Simultaneous Download, Installation, Secure Boot, Severed Fields
    https://tools.ietf.org/html/draft-ietf-suit-manifest-19#appendix-B.3


## CBOR Diagnostic
    / SUIT_Envelope = /
    107({
        / authentication-wrapper / 2: << [
            / digest: / << [
                / algorithm-id: / -16 / SHA-256 /,
                / digest-bytes: / h'86bbcc8823f3a4441956f02b001302f503487461fb77fab086efe31530881f97'
            ] >>,
            / signatures: / << 18([
                / protected: / << {
                    / alg / 1: -7 / ES256 /
                } >>,
                / unprotected: / {
                },
                / payload: / null,
                / signature: / h'8c6bf014b62fa7b80dd5eb2ff7024ab52a116cd1bc0db1f10311b31e7b29e3beae765fad42fb8600fa13a6bf6d5e45929a05a60767f9b7420a5002a05d95e49e'
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
            ] >>,
            / install / 17: [
                / algorithm-id: / -16 / SHA-256 /,
                / digest-bytes: / h'cfa90c5c58595e7f5119a72f803fd0370b3e6abbec6315cd38f63135281bc498'
            ],
            / text / 23: [
                / algorithm-id: / -16 / SHA-256 /,
                / digest-bytes: / h'2bfc4d0cc6680be7dd9f5ca30aa2bb5d1998145de33d54101b80e2ca49faf918'
            ]
        } >>,
        / install / 17: << [
            / directive-override-parameters / 20, {
                / uri / 21: "http://example.com/very/long/path/to/file/file.bin"
            },
            / directive-fetch / 21, 2,
            / condition-image-match / 3, 15
        ] >>,
        / text / 23: << {
            / text-manifest-description / 1: "## Example 2: Simultaneous Download, Installation, Secure Boot, Severed Fields\n\n    This example covers the following templates:\n    \n    * Compatibility Check ({{template-compatibility-check}})\n    * Secure Boot ({{template-secure-boot}})\n    * Firmware Download ({{firmware-download-template}})\n    \n    This example also demonstrates severable elements ({{ovr-severable}}), and text ({{manifest-digest-text}}).",
            [h'00']: {
                / text-vendor-domain / 3: "arm.com",
                / text-component-description / 5: "This component is a demonstration. The digest is a sample pattern, not a real one."
            }
        } >>
    })
