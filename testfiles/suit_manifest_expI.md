
## Integrated Payload Manifest {#suit-integrated}
### CBOR Diagnostic Notation of SUIT Manifest
~~~
/ SUIT_Envelope_Tagged / 107( {
  / suit-authentication-wrapper / 2: << [
    << [
      / suit-digest-algorithm-id: / -16 / cose-alg-sha256 /,
      / suit-digest-bytes: / h'C8363BDF3DCF68F0234A9DD320C2FEA72DE68F46AAE7CE700AFF87085516A335'
    ] >>,
    << / COSE_Sign1_Tagged / 18( [
      / protected: / << {
        / algorithm-id / 1: -7 / ES256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / signature: / h'E0D2973A7B7185BBDA108458FB68EFAF65CD031F2283E784129A95D4229F0EB11F8947D3E589A26CE53CDE0807D58BC976B0FC4AB0E7C0CDE64B13CA41D1D986'
    ] ) >>
  ] >>,
  / suit-integrated-payload / "#tc": h'48656C6C6F2C2053656375726520576F726C6421', / "Hello, Secure World!" /
  / suit-manifest / 3: << {
    / suit-manifest-version / 1: 1,
    / suit-manifest-sequence-number / 2: 3,
    / suit-common / 3: << {
      / suit-components / 2: [
        [
          h'544545502D446576696365',           / "TEEP-Device" /
          h'5365637572654653',                 / "SecureFS" /
          h'8D82573A926D4754935332DC29997F74', / tc-uuid /
          h'7461'                              / "ta" /
        ]
      ],
      / suit-common-sequence / 4: << [
        / suit-directive-set-parameters / 19, {
          / suit-parameter-vendor-identifier / 1: h'C0DDD5F15243566087DB4F5B0AA26C2F',
          / suit-parameter-class-identifier / 2: h'DB42F7093D8C55BAA8C5265FC5820F4E',
          / suit-parameter-image-digest / 3: << [
            / suit-digest-algorithm-id: / -16 / cose-alg-sha256 /,
            / suit-digest-bytes: / h'8CF71AC86AF31BE184EC7A05A411A8C3A14FD9B77A30D046397481469468ECE8'
          ] >>,
          / suit-parameter-image-size / 14: 20
        },
        / suit-condition-vendor-identifier / 1, 15,
        / suit-condition-class-identifier / 2, 15
      ] >>
    } >>,
    / suit-install / 9: << [
      / suit-directive-set-parameters / 19, {
        / suit-parameter-uri / 21: "#tc"
      },
      / suit-directive-fetch / 21, 15,
      / suit-condition-image-match / 3, 15
    ] >>,
    / suit-text / 13: << {
      [
        h'544545502D446576696365',           / "TEEP-Device" /
        h'5365637572654653',                 / "SecureFS" /
        h'8D82573A926D4754935332DC29997F74', / tc-uuid /
        h'7461'                              / "ta" /
      ]: {
        / suit-text-model-name / 2: "Reference TEEP-Device",
        / suit-text-vendor-domain / 3: "tc.org"
      }
    } >>
  } >>
} )
~~~


### CBOR Binary Representation
~~~
D8 6B                                               # tag(107) / SUIT_Envelope_Tagged /
   A3                                               # map(3)
      02                                            # unsigned(2) / suit-authentication-wrapper /
      58 73                                         # bytes(115)
         82                                         # array(2)
            58 24                                   # bytes(36)
               82                                   # array(2)
                  2F                                # negative(15) / -16 = cose-alg-sha256 /
                  58 20                             # bytes(32)
                     C8363BDF3DCF68F0234A9DD320C2FEA72DE68F46AAE7CE700AFF87085516A335
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
                        E0D2973A7B7185BBDA108458FB68EFAF65CD031F2283E784129A95D4229F0EB11F8947D3E589A26CE53CDE0807D58BC976B0FC4AB0E7C0CDE64B13CA41D1D986
      63                                            # text(3) / suit-integrated-payload /
         237463                                     # "#tc"
      54                                            # bytes(20)
         48656C6C6F2C2053656375726520576F726C6421   # "Hello, Secure World!"
      03                                            # unsigned(3) / suit-manifest: /
      58 E8                                         # bytes(232)
         A5                                         # map(5)
            01                                      # unsigned(1) / suit-manifest-version: /
            01                                      # unsigned(1)
            02                                      # unsigned(2) / suit-manifest-sequence-number: /
            03                                      # unsigned(3)
            03                                      # unsigned(3) / suit-common: /
            58 84                                   # bytes(132)
               A2                                   # map(2)
                  02                                # unsigned(2) / suit-components: /
                  81                                # array(1)
                     84                             # array(4)
                        4B                          # bytes(11)
                           544545502D446576696365   # "TEEP-Device"
                        48                          # bytes(8)
                           5365637572654653         # "SecureFS"
                        50                          # bytes(16)
                           8D82573A926D4754935332DC29997F74 # tc-uuid
                        42                          # bytes(2)
                           7461                     # "ta"
                  04                                # unsigned(4) / suit-common-sequence: /
                  58 54                             # bytes(84)
                     86                             # array(6)
                        13                          # unsigned(19) / suit-directive-set-parameters: /
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
                                    8CF71AC86AF31BE184EC7A05A411A8C3A14FD9B77A30D046397481469468ECE8
                           0E                       # unsigned(14) / suit-parameter-image-size: /
                           14                       # unsigned(20)
                        01                          # unsigned(1) / suit-condition-vendor-identifier: /
                        0F                          # unsigned(15)
                        02                          # unsigned(2) / suit-condition-class-identifier: /
                        0F                          # unsigned(15)
            09                                      # unsigned(9) / suit-install: /
            4C                                      # bytes(12)
               86                                   # array(6)
                  13                                # unsigned(19) / suit-directive-set-parameters: /
                  A1                                # map(1)
                     15                             # unsigned(21) / suit-parameter-uri: /
                     63                             # text(3)
                        237463                      # "#tc"
                  15                                # unsigned(21) / suit-directive-fetch: /
                  0F                                # unsigned(15)
                  03                                # unsigned(3) / suit-condition-image-match: /
                  0F                                # unsigned(15)
            0D                                      # unsigned(13) / suit-text: /
            58 4B                                   # bytes(75)
               A1                                   # map(1)
                  84                                # array(4)
                     4B                             # bytes(11)
                        544545502D446576696365      # "TEEP-Device"
                     48                             # bytes(8)
                        5365637572654653            # "SecureFS"
                     50                             # bytes(16)
                        8D82573A926D4754935332DC29997F74 # tc-uuid
                     42                             # bytes(2)
                        7461                        # "ta"
                  A2                                # map(2)
                     02                             # unsigned(2) / suit-model-name: /
                     75                             # text(21)
                        5265666572656E636520544545502D446576696365 # "Reference TEEP-Device"
                     03                             # unsigned(3) / suit-vendor-domain: /
                     66                             # text(6)
                        74632E6F7267                # "tc.org"
~~~


### CBOR Binary in Hex
~~~
D86BA3025873825824822F5820C8363BDF3DCF68F0234A9DD320C2FEA72D
E68F46AAE7CE700AFF87085516A335584AD28443A10126A0F65840E0D297
3A7B7185BBDA108458FB68EFAF65CD031F2283E784129A95D4229F0EB11F
8947D3E589A26CE53CDE0807D58BC976B0FC4AB0E7C0CDE64B13CA41D1D9
86632374635448656C6C6F2C2053656375726520576F726C64210358E8A5
01010203035884A20281844B544545502D44657669636548536563757265
4653508D82573A926D4754935332DC29997F744274610458548613A40150
C0DDD5F15243566087DB4F5B0AA26C2F0250DB42F7093D8C55BAA8C5265F
C5820F4E035824822F58208CF71AC86AF31BE184EC7A05A411A8C3A14FD9
B77A30D046397481469468ECE80E14010F020F094C8613A1156323746315
0F030F0D584BA1844B544545502D44657669636548536563757265465350
8D82573A926D4754935332DC29997F74427461A202755265666572656E63
6520544545502D446576696365036674632E6F7267
~~~
