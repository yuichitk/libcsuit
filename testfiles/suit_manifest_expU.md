
## URI Reference Manifest {#suit-uri}
### CBOR Diagnostic Notation of SUIT Manifest
~~~
/ SUIT_Envelope_Tagged / 107( {
  / suit-authentication-wrapper / 2: << [
    << [
      / suit-digest-algorithm-id: / -16 / suit-cose-alg-sha256 /,
      / suit-digest-bytes: / h'F8690E5A86D010BF2B5348ABB99F2254DB7B608D0D626B98DB51AB3ECFC51907'
    ] >>,
    << / COSE_Sign1_Tagged / 18( [
      / protected: / << {
        / algorithm-id / 1: -7 / ES256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / signature: / h'47B94E8D92E5458AEB0304267ADC95AA21AF67B92D178009E98DD8C8757922147949146C413C9A43B73B3D96D1E9DD4E601004769349D1DDE06AA4F1B9E714A5'
    ] ) >>
  ] >>,
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
        / suit-directive-override-parameters / 20, {
          / suit-parameter-vendor-identifier / 1: h'C0DDD5F15243566087DB4F5B0AA26C2F',
          / suit-parameter-class-identifier / 2: h'DB42F7093D8C55BAA8C5265FC5820F4E',
          / suit-parameter-image-digest / 3: << [
            / suit-digest-algorithm-id: / -16 / suit-cose-alg-sha256 /,
            / suit-digest-bytes: / h'8CF71AC86AF31BE184EC7A05A411A8C3A14FD9B77A30D046397481469468ECE8'
          ] >>,
          / suit-parameter-image-size / 14: 20
        },
        / suit-condition-vendor-identifier / 1, 15,
        / suit-condition-class-identifier / 2, 15
      ] >>
    } >>,
    / suit-install / 9: << [
      / suit-directive-override-parameters / 20, {
        / suit-parameter-uri / 21: "https://tc.org/8d82573a-926d-4754-9353-32dc29997f74.ta"
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
   A2                                               # map(2)
      02                                            # unsigned(2) / suit-authentication-wrapper /
      58 73                                         # bytes(115)
         82                                         # array(2)
            58 24                                   # bytes(36)
               82                                   # array(2)
                  2F                                # negative(15) / -16 = suit-cose-alg-sha256 /
                  58 20                             # bytes(32)
                     F8690E5A86D010BF2B5348ABB99F2254DB7B608D0D626B98DB51AB3ECFC51907
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
                        47B94E8D92E5458AEB0304267ADC95AA21AF67B92D178009E98DD8C8757922147949146C413C9A43B73B3D96D1E9DD4E601004769349D1DDE06AA4F1B9E714A5
      03                                            # unsigned(3) / suit-manifest: /
      59 011D                                       # bytes(285)
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
                                 2F                 # negative(15) / -16 = suit-cose-alg-sha256 /
                                 58 20              # bytes(32)
                                    8CF71AC86AF31BE184EC7A05A411A8C3A14FD9B77A30D046397481469468ECE8
                           0E                       # unsigned(14) / suit-parameter-image-size: /
                           14                       # unsigned(20)
                        01                          # unsigned(1) / suit-condition-vendor-identifier: /
                        0F                          # unsigned(15)
                        02                          # unsigned(2) / suit-condition-class-identifier: /
                        0F                          # unsigned(15)
            09                                      # unsigned(9) / suit-install: /
            58 40                                   # bytes(64)
               86                                   # array(6)
                  14                                # unsigned(20) / suit-directive-override-parameters: /
                  A1                                # map(1)
                     15                             # unsigned(21) / suit-parameter-uri: /
                     78 36                          # text(54)
                        68747470733A2F2F74632E6F72672F38643832353733612D393236642D343735342D393335332D3332646332393939376637342E7461 # "https://tc.org/8d82573a-926d-4754-9353-32dc29997f74.ta"
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
                     02                             # unsigned(2) / suit-text-model-name: /
                     75                             # text(21)
                        5265666572656E636520544545502D446576696365 # "Reference TEEP-Device"
                     03                             # unsigned(3) / suit-text-vendor-domain: /
                     66                             # text(6)
                        74632E6F7267                # "tc.org"
~~~


### CBOR Binary in Hex
~~~
D86BA2025873825824822F58208ADC995573631639C3C6D5FC4026160C8A
32C5AADFBEEC9FA49E026FDD74CAB3584AD28443A10126A0F658406AC8F0
FA591D11E92C28D68689384B6317C665AC3636B2A16A9A8244E750EA55C4
1492FAE1DF7008584CFB19CF0AD9D56B9562A044F9254DADC698D718FC40
030359011DA501010203035884A20281844B544545502D44657669636548
5365637572654653508D82573A926D4754935332DC29997F744274610458
548613A40150C0DDD5F15243566087DB4F5B0AA26C2F0250DB42F7093D8C
55BAA8C5265FC5820F4E035824822F58208CF71AC86AF31BE184EC7A05A4
11A8C3A14FD9B77A30D046397481469468ECE80E14010F020F0958408613
A115783668747470733A2F2F74632E6F72672F38643832353733612D3932
36642D343735342D393335332D3332646332393939376637342E7461150F
030F0D584BA1844B544545502D446576696365485365637572654653508D
82573A926D4754935332DC29997F74427461A202755265666572656E6365
20544545502D446576696365036674632E6F7267
~~~
D86BA2025873825824822F5820F8690E5A86D010BF2B5348ABB99F2254DB
7B608D0D626B98DB51AB3ECFC51907584AD28443A10126A0F6584047B94E
8D92E5458AEB0304267ADC95AA21AF67B92D178009E98DD8C87579221479
49146C413C9A43B73B3D96D1E9DD4E601004769349D1DDE06AA4F1B9E714
A50359011DA501010203035884A20281844B544545502D44657669636548
5365637572654653508D82573A926D4754935332DC29997F744274610458
548614A40150C0DDD5F15243566087DB4F5B0AA26C2F0250DB42F7093D8C
55BAA8C5265FC5820F4E035824822F58208CF71AC86AF31BE184EC7A05A4
11A8C3A14FD9B77A30D046397481469468ECE80E14010F020F0958408614
A115783668747470733A2F2F74632E6F72672F38643832353733612D3932
36642D343735342D393335332D3332646332393939376637342E7461150F
030F0D584BA1844B544545502D446576696365485365637572654653508D
82573A926D4754935332DC29997F74427461A202755265666572656E6365
20544545502D446576696365036674632E6F7267
~~~
