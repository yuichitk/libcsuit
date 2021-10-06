
## Example 3: Supplying Personalization Data for Trusted Component Binary {#suit-personalization}

### CBOR Diagnostic Notation of SUIT Manifest

~~~
/ SUIT_Envelope_Tagged / 107 ( {
  / suit-authentication-wrapper / 2: << [
    << [
      / suit-digest-algorithm-id: / -16 / cose-alg-sha256 /,
      / suit-digest-bytes: / h'A810FBAFCAC8C7E107AD974DDC6FDB4D516B810569A47A7E47B4B6E9BCA98CA1'
    ] >>,
    << / COSE_Sign1_Tagged / 18 ( [
      / protected: / << {
        / algorithm-id / 1: -7 / ES256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / signature: / h'E0F4D43B9CF2E837F58E925AD8041BC64F48C8934537F0CC5E19A8044790B7001FA481C5A7C9DEE8E87633CA2677A2896B15E72086A7CFBC6B4A453C312226F2'
    ] ) >>
  ] >>,
  / suit-manifest / 3: << {
    / suit-manifest-version / 1: 1,
    / suit-manifest-sequence-number / 2: 3,
    / suit-common / 3: << {
      / suit-dependencies / 1: [
        {
          / suit-dependency-digest / 1: [
            / suit-digest-algorithm-id: / -16 / cose-alg-sha256 /,
            / suit-digest-bytes: / h'8ADC995573631639C3C6D5FC4026160C8A32C5AADFBEEC9FA49E026FDD74CAB3'
          ]
        }
      ],
      / suit-components / 2: [
        [
          h'544545502D446576696365', / "TEEP-Device" /
          h'5365637572654653',       / "SecureFS" /
          h'636F6E6669672E6A736F6E'  / "config.json" /
        ]
      ],
      / suit-common-sequence / 4: << [
        / suit-directive-set-component-index / 12, 0,
        / suit-directive-override-parameters / 20, {
          / suit-parameter-vendor-identifier / 1: h'C0DDD5F15243566087DB4F5B0AA26C2F',
          / suit-parameter-class-identifier / 2: h'DB42F7093D8C55BAA8C5265FC5820F4E',
          / suit-parameter-image-digest / 3: << [
            / suit-digest-algorithm-id: / -16 / cose-alg-sha256 /,
            / suit-digest-bytes: / h'AAABCCCDEEEF00012223444566678889ABBBCDDDEFFF01112333455567778999'
          ] >>,
          / suit-parameter-image-size / 14: 64
        },
        / suit-condition-vendor-idnetifier / 1, 15,
        / suit-condition-class-identifier / 2, 15
      ] >>
    } >>,
    / suit-dependency-resolution / 7: << [
      / suit-directive-set-dependency-index / 13, 0,
      / suit-directive-set-parameters / 19, {
        / suit-parameter-uri / 21: "https://tc.org/8d82573a-926d-4754-9353-32dc29997f74.suit"
      },
      / suit-directive-fetch / 21, 2,
      / suit-condition-image-match / 3, 15
    ] >>,
    / suit-install / 9: << [
      / suit-directive-set-dependency-index / 13, 0,
      / suit-directive-process-dependency / 18, 0,
      / suit-directive-set-component-index / 12, 0,
      / suit-directive-set-parameters / 19, {
        / suit-parameter-uri / 21: "https://tc.org/config.json"
      },
      / suit-directive-fetch / 21, 2,
      / suit-condition-image-match / 3, 15
    ] >>,
    / suit-validate / 10: << [
      / suit-directive-set-component-index / 12, 0,
      / suit-condition-image-match/ 3, 15
    ] >>,
    / suit-text / 13: << {
      [
        h'544545502D446576696365', / "TEEP-Device" /
        h'5365637572654653',       / "SecureFS" /
        h'636F6E6669672E6A736F6E'  / "config.json" /
      ]: {
        / suit-text-model-name / 2: "Reference TEEP-Device",
        / suit-text-vendor-domain / 3: "tc.org"
      }
    } >>
  } >>
} )
~~~


### CBOR Binary Represenation

~~~
D8 6B                                               # tag(107) / SUIT_Envelope_Tagged /
   A2                                               # map(2)
      02                                            # unsigned(2) / suit-authentication-wrapper: /
      58 73                                         # bytes(115)
         82                                         # array(2)
            58 24                                   # bytes(36)
               82                                   # array(2)
                  2F                                # negative(15) / -16 = cose-alg-sha256 /
                  58 20                             # bytes(32)
                     A810FBAFCAC8C7E107AD974DDC6FDB4D516B810569A47A7E47B4B6E9BCA98CA1
            58 4A                                   # bytes(74)
               D2                                   # tag(18) / COSE_Sign1_Tagged /
                  84                                # array(4)
                     43                             # bytes(3)
                        A1                          # map(1)
                           01                       # unsigned(1) / algorithm-id /
                           26                       # negative(6) / -7 = ES256 /
                     A0                             # map(0)
                     F6                             # primitive(22) / null /
                     58 40                          # bytes(64)
                        E0F4D43B9CF2E837F58E925AD8041BC64F48C8934537F0CC5E19A8044790B7001FA481C5A7C9DEE8E87633CA2677A2896B15E72086A7CFBC6B4A453C312226F2
      03                                            # unsigned(3) / suit-manifest: /
      59 0170                                       # bytes(368)
         A7                                         # map(7)
            01                                      # unsigned(1) / suit-manifest-version: /
            01                                      # unsigned(1)
            02                                      # unsigned(2) / suit-manifest-sequence-number: /
            03                                      # unsigned(3)
            03                                      # unsigned(3) / suit-common: /
            58 A7                                   # bytes(167)
               A3                                   # map(3)
                  01                                # unsigned(1) / suit-dependencies: /
                  81                                # array(1)
                     A1                             # map(1)
                        01                          # unsigned(1) suit-dependency-digest: /
                        82                          # array(2)
                           2F                       # negative(15) / -16 = cose-alg-sha256 /
                           58 20                    # bytes(32)
                              8ADC995573631639C3C6D5FC4026160C8A32C5AADFBEEC9FA49E026FDD74CAB3
                  02                                # unsigned(2) / suit-components: /
                  81                                # array(1)
                     83                             # array(3)
                        4B                          # bytes(11)
                           544545502D446576696365   # "TEEP-Device"
                        48                          # bytes(8)
                           5365637572654653         # "SecureFS"
                        4B                          # bytes(11)
                           636F6E6669672E6A736F6E   # "config.json"
                  04                                # unsigned(4) / suit-common-sequence: /
                  58 57                             # bytes(87)
                     88                             # array(8)
                        0C                          # unsigned(12) / suit-directive-set-component-index: /
                        00                          # unsigned(0)
                        14                          # unsigned(20) / suit-directive-override-parameters: /
                        A4                          # map(4)
                           01                       # unsigned(1) / suit-parameter-vendor-identifier: /
                           50                       # bytes(16)
                              C0DDD5F15243566087DB4F5B0AA26C2F
                           02                       # unsigned(2) / suit-parameter-class-identifier: /
                           50                       # bytes(16)
                              DB42F7093D8C55BAA8C5265FC5820F4E
                           03                       # unsigned(3) / suit-parameter-image-digest: /
                           58 24                    # bytes(36)
                              82                    # array(2)
                                 2F                 # negative(15) / -16 = cose-alg-sha256 /
                                 58 20              # bytes(32)
                                    AAABCCCDEEEF00012223444566678889ABBBCDDDEFFF01112333455567778999
                           0E                       # unsigned(14) / suit-parameter-image-size: /
                           18 40                    # unsigned(64)
                        01                          # unsigned(1) / suit-condition-vendor-identifier: /
                        0F                          # unsigned(15)
                        02                          # unsigned(2) / suit-condition-class-identifier: /
                        0F                          # unsigned(15)
            07                                      # unsigned(7) / suit-dependency-resolution: /
            58 44                                   # bytes(68)
               88                                   # array(8)
                  0D                                # unsigned(13) / suit-directive-set-dependency-index: /
                  00                                # unsigned(0)
                  13                                # unsigned(19) / suit-directive-set-parameters: /
                  A1                                # map(1)
                     15                             # unsigned(21) / suit-parameter-uri: /
                     78 38                          # text(56)
                        68747470733A2F2F74632E6F72672F38643832353733612D393236642D343735342D393335332D3332646332393939376637342E73756974 # "https://tc.org/8d82573a-926d-4754-9353-32dc29997f74.suit"
                  15                                # unsigned(21) / suit-directive-fetch: /
                  02                                # unsigned(2)
                  03                                # unsigned(3) / suit-condition-image-match: /
                  0F                                # unsigned(15)
            09                                      # unsigned(9) / suit-install: /
            58 2A                                   # bytes(42)
               8C                                   # array(12)
                  0D                                # unsigned(13) / suit-directive-set-dependency-index: /
                  00                                # unsigned(0)
                  12                                # unsigned(18) / suit-directive-process-dependency: /
                  00                                # unsigned(0)
                  0C                                # unsigned(12) / suit-directive-set-component-index: /
                  00                                # unsigned(0)
                  13                                # unsigned(19) / suit-directive-set-parameters: /
                  A1                                # map(1)
                     15                             # unsigned(21) / suit-parameter-uri: /
                     78 1A                          # text(26)
                        68747470733A2F2F74632E6F72672F636F6E6669672E6A736F6E # "https://tc.org/config.json"
                  15                                # unsigned(21) / suit-directive-fetch: /
                  02                                # unsigned(2)
                  03                                # unsigned(3) / suit-condition-image-match: /
                  0F                                # unsigned(15)
            0A                                      # unsigned(10) / suit-validate: /
            45                                      # bytes(5)
               84                                   # array(4)
                  0C                                # unsigned(12) / suit-directive-set-component-index: /
                  00
                  03                                # unsigned(3) / suit-condition-image-match: /
                  0F                                # unsigned(15)
            0D                                      # unsigned(13) / suit-text: /
            58 43                                   # bytes(67)
               A1                                   # map(1)
                  83                                # array(3)
                     4B                             # bytes(11)
                        544545502D446576696365      # "TEEP-Device"
                     48                             # bytes(8)
                        5365637572654653            # "SecureFS"
                     4B                             # bytes(11)
                        636F6E6669672E6A736F6E      # "config.json"
                  A2                                # map(2)
                     02                             # unsigned(2) / suit-text-model-name: /
                     75                             # text(21)
                        5265666572656E636520544545502D446576696365 # "Reference TEEP-Device"
                     03                             # unsigned(3) / suit-text-vendor-domain: /
                     66                             # text(6)
                        74632E6F7267                # "tc.org"
~~~


### CBOR Binary in Hex

~~~
D86BA2025873825824822F5820A810FBAFCAC8C7E107AD974DDC6FDB4D51
6B810569A47A7E47B4B6E9BCA98CA1584AD28443A10126A0F65840E0F4D4
3B9CF2E837F58E925AD8041BC64F48C8934537F0CC5E19A8044790B7001F
A481C5A7C9DEE8E87633CA2677A2896B15E72086A7CFBC6B4A453C312226
F203590170A7010102030358A7A30181A101822F58208ADC995573631639
C3C6D5FC4026160C8A32C5AADFBEEC9FA49E026FDD74CAB30281834B5445
45502D4465766963654853656375726546534B636F6E6669672E6A736F6E
045857880C0014A40150C0DDD5F15243566087DB4F5B0AA26C2F0250DB42
F7093D8C55BAA8C5265FC5820F4E035824822F5820AAABCCCDEEEF000122
23444566678889ABBBCDDDEFFF011123334555677789990E1840010F020F
075844880D0013A115783868747470733A2F2F74632E6F72672F38643832
353733612D393236642D343735342D393335332D33326463323939393766
37342E737569741502030F09582A8C0D0012000C0013A115781A68747470
733A2F2F74632E6F72672F636F6E6669672E6A736F6E1502030F0A45840C
00030F0D5843A1834B544545502D4465766963654853656375726546534B
636F6E6669672E6A736F6EA202755265666572656E636520544545502D44
6576696365036674632E6F7267
~~~
