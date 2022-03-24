
## E.4. Example 4: Unlink a Trusted Component {#suit-unlink}
{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
/ SUIT_Envelope_Tagged / 107( {
  / suit-authentication-wrapper / 2: << [
    << [
      / suit-digest-algorithm-id: / -16 / suit-cose-alg-sha256 /,
      / suit-digest-bytes: / h'632454F19A9440A5B83493628A7EF8704C8A0205A62C34E425BAA34C71341F42'
    ] >>,
    << / COSE_Sign1_Tagged / 18( [
      / protected / << {
        / algorithm-id / 1: -7 / ES256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / signature: / h'A32CDB7C1D089C27408CED3C79087220EB0D77F105BB5330912875F4D94AD108D7658C650463AEB7E1CCA5084F22B2F3993176E8B3529A3202ED735E4D39BBBF'
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
    ] >>
  } >>
} )
~~~~


### CBOR Binary Representation
{: numbered='no'}

~~~~
D8 6B                                               # tag(107) / SUIT_Envelope_Tagged /
   A2                                               # map(2)
      02                                            # unsigned(2) / suit-authentication-wrapper /
      58 73                                         # bytes(115)
         82                                         # array(2)
            58 24                                   # bytes(36)
               82                                   # array(2)
                  2F                                # negative(15) / -16 = suit-cose-alg-sha256 /
                  58 20                             # bytes(32)
                     632454F19A9440A5B83493628A7EF8704C8A0205A62C34E425BAA34C71341F42
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
                        A32CDB7C1D089C27408CED3C79087220EB0D77F105BB5330912875F4D94AD108D7658C650463AEB7E1CCA5084F22B2F3993176E8B3529A3202ED735E4D39BBBF
      03                                            # unsigned(3) / suit-manifest: /
      58 73                                         # bytes(115)
         A4                                         # map(4)
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
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
D86BA2025873825824822F5820632454F19A9440A5B83493628A7EF8704C
8A0205A62C34E425BAA34C71341F42584AD28443A10126A0F65840A32CDB
7C1D089C27408CED3C79087220EB0D77F105BB5330912875F4D94AD108D7
658C650463AEB7E1CCA5084F22B2F3993176E8B3529A3202ED735E4D39BB
BF035873A40101021BFFFFFFFFFFFFFFFF03585BA20281844B544545502D
446576696365485365637572654653508D82573A926D4754935332DC2999
7F7442746104582B8614A20150C0DDD5F15243566087DB4F5B0AA26C2F02
50DB42F7093D8C55BAA8C5265FC5820F4E010F020F0946840C00182100
~~~~
