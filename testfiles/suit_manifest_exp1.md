<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# SUIT Manifest
    https://tools.ietf.org/html/draft-ietf-suit-manifest-07#appendix-B.2

## CBOR Diagnostic
    / SUIT_Envelope = /
    {
        / suit-authentication-wrapper : SUIT_Authentication_Wrapper /
        2: h'81586FD28443A10126A058248202582081532771898E4EBCCCF12C607420EBA62B5086192CAC4C99692835B58EE62F7B5840815921E5148E9B81E79D8BE570DE6BB42BA2E903C8549F0E13DEE4D0EE420D90DD9F8537EBEAD3F92B37DF703539879129183B0BEAF3BA75CACD8A91E075A24E',
        / suit-manifest : SUIT_Manifest /
        3: h'A501010202035860A20244818141000458568614A40150FA6B4A53D5AD5FDFBE9DE663E4D41FFE02501492AF1425695E48BF429B2D51F2AB450358248202582000112233445566778899AABBCCDDEEFF0123456789ABCDEFFEDCBA98765432100E1987D001F602F60958258613A115781B687474703A2F2F6578616D706C652E636F6D2F66696C652E62696E15F603F60A438203F6'
    }

    / SUIT_Authentication_Wrapper = /
    [
        / SUIT_Authentication_Block  /
        h'D28443A10126A058248202582081532771898E4EBCCCF12C607420EBA62B5086192CAC4C99692835B58EE62F7B5840815921E5148E9B81E79D8BE570DE6BB42BA2E903C8549F0E13DEE4D0EE420D90DD9F8537EBEAD3F92B37DF703539879129183B0BEAF3BA75CACD8A91E075A24E'
    ]
    / SUIT_Authentication_Block  = /
    18([
        / protected : ES256 /
        h'A10126',
        / unprotected : nil /
        {},
        / payload : SUIT_Digest /
        h'8202582081532771898E4EBCCCF12C607420EBA62B5086192CAC4C99692835B58EE62F7B',
        / signature : bstr /
        h'815921E5148E9B81E79D8BE570DE6BB42BA2E903C8549F0E13DEE4D0EE420D90DD9F8537EBEAD3F92B37DF703539879129183B0BEAF3BA75CACD8A91E075A24E'
    ])
    / SUIT_Digest = /
    [
        / suit-digest-algorithm-id : algorithm-id-sha256 /
        2,
        / suit-digest-bytes : bstr /
        h'81532771898E4EBCCCF12C607420EBA62B5086192CAC4C99692835B58EE62F7B'
    ]

    / SUIT_Manifest = /
    {
        / suit-manifest-version : 1 /
        1: 1,
        / suit-manifest-sequence-number : 2 /
        2: 2,
        / suit-common : SUIT_Common /
        3: h'A20244818141000458568614A40150FA6B4A53D5AD5FDFBE9DE663E4D41FFE02501492AF1425695E48BF429B2D51F2AB450358248202582000112233445566778899AABBCCDDEEFF0123456789ABCDEFFEDCBA98765432100E1987D001F602F6',
        / suit-install : SUIT_Severable_Command_Sequence /
        9: h'8613A115781B687474703A2F2F6578616D706C652E636F6D2F66696C652E62696E15F603F6',
        / suit-validate : SUIT_Command_Sequence  /
        10: h'8203F6'
    }
    / SUIT_Common = /
    {
        / suit-components : [[h'00']] /
        2 : h'81814100',
        / suit-common-sequence : SUIT_Command_Sequence /
        4 : h'8614A40150FA6B4A53D5AD5FDFBE9DE663E4D41FFE02501492AF1425695E48BF429B2D51F2AB450358248202582000112233445566778899AABBCCDDEEFF0123456789ABCDEFFEDCBA98765432100E1987D001F602F6'
    }
    / suit-common-sequence : SUIT_Command_Sequence = /
    [
        / suit-directive-override-parameters : {+ SUIT_Parameters} /
        20, {
            / suit-parameter-vendor-identifier : RFC4122_UUID /
            1: h'FA6B4A53D5AD5FDFBE9DE663E4D41FFE',
            / suit-parameter-class-identifier : RFC4122_UUID /
            2: h'1492AF1425695E48BF429B2D51F2AB45',
            / suit-parameter-image-digest : SUIT_Digest /
            3: h'8202582000112233445566778899AABBCCDDEEFF0123456789ABCDEFFEDCBA9876543210',
            / suit-parameter-image-size : uint /
            14: 34768
        },
        / suit-condition-vendor-identifier : null /
        1, null,
        / suit-condition-class-identifier : null /
        2, null
    ]
    / suit-install : SUIT_Severable_Command_Sequence = /
    [
        / suit-directive-set-parameters : {+ SUIT_Parameters} /
        19, {21: "http://example.com/file.bin"},
        / suit-directive-fetch : null /
        21, null,
        / suit-condition-image-match : null /
        3, null
    ]
    / suit-validate : SUIT_Command_Sequence /
    [
        / suit-condition-image-match : null /
        3, null
    ]

## CBOR binary
    A2                                      # map(2)
       02                                   # unsigned(2)
       58 72                                # bytes(114)
          81586FD28443A10126A058248202582081532771898E4EBCCCF12C607420EBA62B5086192CAC4C99692835B58EE62F7B5840815921E5148E9B81E79D8BE570DE6BB42BA2E903C8549F0E13DEE4D0EE420D90DD9F8537EBEAD3F92B37DF703539879129183B0BEAF3BA75CACD8A91E075A24E
       03                                   # unsigned(3)
       58 95                                # bytes(149)
          A501010202035860A20244818141000458568614A40150FA6B4A53D5AD5FDFBE9DE663E4D41FFE02501492AF1425695E48BF429B2D51F2AB450358248202582000112233445566778899AABBCCDDEEFF0123456789ABCDEFFEDCBA98765432100E1987D001F602F60958258613A115781B687474703A2F2F6578616D706C652E636F6D2F66696C652E62696E15F603F60A438203F6

## Command
    echo -en "\xa2\x02\x58\x72\x81\x58\x6f\xd2\x84\x43\xa1\x01\x26\xa0\x58\x24\x82\x02\x58\x20\x81\x53\x27\x71\x89\x8e\x4e\xbc\xcc\xf1\x2c\x60\x74\x20\xeb\xa6\x2b\x50\x86\x19\x2c\xac\x4c\x99\x69\x28\x35\xb5\x8e\xe6\x2f\x7b\x58\x40\x81\x59\x21\xe5\x14\x8e\x9b\x81\xe7\x9d\x8b\xe5\x70\xde\x6b\xb4\x2b\xa2\xe9\x03\xc8\x54\x9f\x0e\x13\xde\xe4\xd0\xee\x42\x0d\x90\xdd\x9f\x85\x37\xeb\xea\xd3\xf9\x2b\x37\xdf\x70\x35\x39\x87\x91\x29\x18\x3b\x0b\xea\xf3\xba\x75\xca\xcd\x8a\x91\xe0\x75\xa2\x4e\x03\x58\x95\xa5\x01\x01\x02\x02\x03\x58\x60\xa2\x02\x44\x81\x81\x41\x00\x04\x58\x56\x86\x14\xa4\x01\x50\xfa\x6b\x4a\x53\xd5\xad\x5f\xdf\xbe\x9d\xe6\x63\xe4\xd4\x1f\xfe\x02\x50\x14\x92\xaf\x14\x25\x69\x5e\x48\xbf\x42\x9b\x2d\x51\xf2\xab\x45\x03\x58\x24\x82\x02\x58\x20\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10\x0e\x19\x87\xd0\x01\xf6\x02\xf6\x09\x58\x25\x86\x13\xa1\x15\x78\x1b\x68\x74\x74\x70\x3a\x2f\x2f\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d\x2f\x66\x69\x6c\x65\x2e\x62\x69\x6e\x15\xf6\x03\xf6\x0a\x43\x82\x03\xf6" > suit_manifest_1.cbor
