
## Delete Component Manifest {#suit-delete}
### CBOR Diagnostic Notation of SUIT Manifest
~~~
/ SUIT_Envelope_Tagged / 107( {
  / suit-authentication-wrapper / 2: << [
    << [
      / suit-digest-algorithm-id: / -16 / suit-cose-alg-sha256 /,
      / suit-digest-bytes: / h'A43F25C8CC203A23FA417926505019F1A12F50BE98611F3580F4FFB167FD5159'
    ] >>,
    << / COSE_Sign1_Tagged / 18( [
      / protected / << {
        / algorithm-id / 1: -7 / ES256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / signature: / h'90348818705F68725C31F5EA70B2E52A97A0466534CD2E1F790321ADC2407924DB0EB5AA8E0B5123798F55A12C5447ED0B162C46569903DB659BE70A55DFED3D'
    ] ) >>
  ] >>,
  / suit-manifest / 3: << {
    / suit-manifest-version / 1: 1,
    / suit-manifest-sequence-number / 2: 18446744073709551615 / UINT64_MAX /,
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
        / suit-directive-override-parameters / 20, {
          / suit-parameter-vendor-identifier / 1: h'C0DDD5F15243566087DB4F5B0AA26C2F',
          / suit-parameter-class-identifier / 2: h'DB42F7093D8C55BAA8C5265FC5820F4E'
        },
        / suit-condition-vendor-identifier / 1, 15,
        / suit-condition-class-identifier / 2, 15
      ] >>
    } >>,
    / suit-install / 9: << [
      / suit-directive-set-component-index: / 12, 0,
      / suit-directive-unlink: / 33, 0
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
   A2                                               # map(2)
      02                                            # unsigned(2) / suit-authentication-wrapper /
      58 73                                         # bytes(115)
         82                                         # array(2)
            58 24                                   # bytes(36)
               82                                   # array(2)
                  2F                                # negative(15) / -16 = suit-cose-alg-sha256 /
                  58 20                             # bytes(32)
                     A43F25C8CC203A23FA417926505019F1A12F50BE98611F3580F4FFB167FD5159
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
                        90348818705F68725C31F5EA70B2E52A97A0466534CD2E1F790321ADC2407924DB0EB5AA8E0B5123798F55A12C5447ED0B162C46569903DB659BE70A55DFED3D
      03                                            # unsigned(3) / suit-manifest: /
      58 C1                                         # bytes(193)
         A5                                         # map(5)
            01                                      # unsigned(1) / suit-manifest-version: /
            01                                      # unsigned(1)
            02                                      # unsigned(2) / suit-manifest-sequence-number: /
            1B FFFFFFFFFFFFFFFF                     # unsigned(18446744073709551615)
            03                                      # unsigned(3) / suit-common: /
            58 5B                                   # bytes(91)
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
                  58 2B                             # bytes(84)
                     86                             # array(6)
                        14                          # unsigned(20) / suit-directive-override-parameters: /
                        A2                          # map(2)
                           01                       # unsigned(1) / suit-parameter-vendor-identifier: /
                           50                       # bytes(16)
                              C0DDD5F15243566087DB4F5B0AA26C2F
                           02                       # unsigned(2) / suit-parameter-class-identifier: /
                           50                       # bytes(16)
                              DB42F7093D8C55BAA8C5265FC5820F4E
                        01                          # unsigned(1) / suit-condition-vendor-identifier: /
                        0F                          # unsigned(15)
                        02                          # unsigned(2) / suit-condition-class-identifier: /
                        0F                          # unsigned(15)
            09                                      # unsigned(9) / suit-install: /
            46                                      # bytes(6)
               84                                   # array(4)
                  0C                                # unsigned(12) / suit-directive-set-component-index: /
                  00                                # unsigned(0)
                  18 21                             # unsigned(33) / suit-directive-unlink: /
                  00                                # unsigned(0)
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
                     02                             # unsigned(2) / suit-text-model-name: /
                     75                             # text(21)
                        5265666572656E636520544545502D446576696365 # "Reference TEEP-Device"
                     03                             # unsigned(3) / suit-text-vendor-domain: /
                     66                             # text(6)
                        74632E6F7267                # "tc.org"
~~~


### CBOR Binary in Hex
~~~
D86BA2025873825824822F58200F2AA1B386F11E5DDD3D6796C89C775F2D
C450594C45219589753B2C8F393A54584AD28443A10126A0F6584036C6D3
80AD9E58F9E82A039C5B2C99B801344BC065215928BD4E1C142953357625
02DD8C5237B350F9A6147B39BEBCF856BED27F382D22F5A1427E2C5BE707
B50358C1A50101021BFFFFFFFFFFFFFFFF03585BA20281844B544545502D
446576696365485365637572654653508D82573A926D4754935332DC2999
7F7442746104582B8613A20150C0DDD5F15243566087DB4F5B0AA26C2F02
50DB42F7093D8C55BAA8C5265FC5820F4E010F020F0946840C001821000D
584BA1844B544545502D446576696365485365637572654653508D82573A
926D4754935332DC29997F74427461A202755265666572656E6365205445
45502D446576696365036674632E6F7267
~~~
D86BA2025873825824822F5820A43F25C8CC203A23FA417926505019F1A1
2F50BE98611F3580F4FFB167FD5159584AD28443A10126A0F65840903488
18705F68725C31F5EA70B2E52A97A0466534CD2E1F790321ADC2407924DB
0EB5AA8E0B5123798F55A12C5447ED0B162C46569903DB659BE70A55DFED
3D0358C1A50101021BFFFFFFFFFFFFFFFF03585BA20281844B544545502D
446576696365485365637572654653508D82573A926D4754935332DC2999
7F7442746104582B8614A20150C0DDD5F15243566087DB4F5B0AA26C2F02
50DB42F7093D8C55BAA8C5265FC5820F4E010F020F0946840C001821000D
584BA1844B544545502D446576696365485365637572654653508D82573A
926D4754935332DC29997F74427461A202755265666572656E6365205445
45502D446576696365036674632E6F7267
~~~
