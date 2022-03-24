
## Example 4: Combined SUIT Manifests with Integrated-Dependency {#suit-integrated-dependency}
{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
/ SUIT_Envelope_Tagged / 107( {
  / suit-authentication-wrapper / 2: << [
    << [
      / suit-digest-algorithm-id: / -16 / suit-cose-alg-sha256 /,
      / suit-digest-bytes: / h'844CA9D399193FB8BA987CBCD340D8F0049640BEBAF8BB6FC06E1CAD10FD9179'
    ] >>,
    << / COSE_Sign1_Tagged / 18( [
      / protected: / << {
        / algorithm-id / 1: -7 / ES256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / signature: / h'5028EEBA1F5B1DCA1BBEEA62C1ED461BB9FEB6BBFD1A71BE06B8EDF226C298A41B6CE4727CCB4E92788F5DA764C5CDE7E9D45E66091EBD33ECDCD2FFF6F713ED'
    ] ) >>
  ] >>,
  / suit-integrated-dependency / "#depending": << / SUIT_Envelope_Tagged / 107( {
    2: << [
      << [
        / suit-digest-algorithm-id: / -16 / suit-cose-alg-sha256 /,
        / suit-digest-bytes: / h'14A98BE957DE38FAE37376EA491FD6CAD9BFBD3C90051C8F5B017D7A496C3B05'
      ] >>,
      << / COSE_Sign1_Tagged / 18( [
        / protected: / << {
          / algorithm-id / 1: -7 / ES256 /
        } >>,
        / unprotected: / {},
        / payload: / null,
        / signature: / h'4093B323953785981EB607C8BA61B21E5C4F85726A2AF48C1CB05BD4401B1B1565070728FDA38E6496D631E1D23F966CFF7805EDE721D48507D9192993DA8722'
      ] ) >>
    ] >>,
    / suit-integrated-payload / "#tc": h'48656C6C6F2C2053656375726520576F726C6421',
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
          / suit-parameter-uri / 21: "#tc"
        },
        / suit-directive-fetch / 21, 15,
        / suit-condition-image-match / 3, 15
      ] >>
    } >>
  }) >>,
  / suit-manifest / 3: << {
    / suit-manifest-version / 1: 1,
    / suit-manifest-sequence-number / 2: 3,
    / suit-common / 3: << {
      / suit-dependencies / 1: [
        {
          / suit-dependency-digest / 1: [
            / suit-digest-algorithm-id / -16 / suit-cose-alg-sha256 /,
            / suit-digest-bytes / h'14A98BE957DE38FAE37376EA491FD6CAD9BFBD3C90051C8F5B017D7A496C3B05'
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
            / suit-digest-algorithm-id: / -16 / suit-cose-alg-sha256 /,
            / suit-digest-bytes: / h'AAABCCCDEEEF00012223444566678889ABBBCDDDEFFF01112333455567778999'
          ] >>,
          / suit-parameter-image-size / 14: 64
        },
        / suit-condition-vendor-identifier / 1, 15,
        / suit-condition-class-identifier / 2, 15
      ] >>
    } >>,
    / suit-dependency-resolution / 7: << [
      / suit-directive-set-dependency-index / 13, 0,
      / suit-directive-set-override-parameters / 20, {
        / suit-parameter-uri / 21: "#depending"
      },
      / suit-directive-fetch / 21, 2,
      / suit-condition-image-match / 3, 15
    ] >>,
    / suit-install / 9: << [
      / suit-directive-set-dependency-index / 13, 0,
      / suit-directive-process-dependency / 18, 0,
      / suit-directive-set-component-index / 12, 0,
      / suit-directive-override-parameters / 20, {
        / suit-parameter-uri / 21: "https://example.org/config.json"
      },
      / suit-directive-fetch / 21, 2,
      / suit-condition-image-match / 3, 15
    ] >>,
    / suit-validate / 10: << [
      / suit-directive-set-component-index / 12, 0,
      / suit-condition-image-match / 3, 15
    ] >>
  } >>
} )
~~~~


### CBOR Binary Representation
{: numbered='no'}

~~~~
D8 6B                                               # tag(107) / SUIT_Envelope_Tagged /
   A3                                               # map(3)
      02                                            # unsigned(2) / suit-authentication-wrapper: /
      58 73                                         # bytes(115)
         82                                         # array(2)
            58 24                                   # bytes(36)
               82                                   # array(2)
                  2F                                # negative(15) / -16 = suit-cose-alg-sha256 /
                  58 20                             # bytes(32)
                     844CA9D399193FB8BA987CBCD340D8F0049640BEBAF8BB6FC06E1CAD10FD9179
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
                        5028EEBA1F5B1DCA1BBEEA62C1ED461BB9FEB6BBFD1A71BE06B8EDF226C298A41B6CE4727CCB4E92788F5DA764C5CDE7E9D45E66091EBD33ECDCD2FFF6F713ED
      6A                                            # text(10)
         23646570656E64696E67                       # "#depending"
      59 012F                                       # bytes(303)
         D8 6B                                      # tag(107) / SUIT_Envelope_Tagged /
            A3                                      # map(3)
               02                                   # unsigned(2) / suit-authentication-wrapper /
               58 73                                # bytes(115)
                  82                                # array(2)
                     58 24                          # bytes(36)
                        82                          # array(2)
                           2F                       # negative(15) / -16 = suit-cose-alg-sha256 /
                           58 20                    # bytes(32)
                              14A98BE957DE38FAE37376EA491FD6CAD9BFBD3C90051C8F5B017D7A496C3B05
                     58 4A                          # bytes(74)
                        D2                          # tag(18) / COSE_Sign1_Tagged /
                           84                       # array(4)
                              43                    # bytes(3)
                                 A1                 # map(1)
                                    01              # unsigned(1) / algorithm-id /
                                    26              # negative(6) / -7 = ES256 /
                              A0                    # map(0)
                              F6                    # primitive(22) / null /
                              58 40                 # bytes(64)
                                 4093B323953785981EB607C8BA61B21E5C4F85726A2AF48C1CB05BD4401B1B1565070728FDA38E6496D631E1D23F966CFF7805EDE721D48507D9192993DA8722
               63                                   # text(3) / suit-integrated-payload /
                  237463                            # "#tc"
               54                                   # bytes(20)
                  48656C6C6F2C2053656375726520576F726C6421 # "Hello, Secure World!"
               03                                   # unsigned(3) / suit-manifest: /
               58 9A                                # bytes(154)
                  A4                                # map(4)
                     01                             # unsigned(1) / suit-manifest-version: /
                     01                             # unsigned(1)
                     02                             # unsigned(2) / suit-manifest-sequence-number: /
                     03                             # unsigned(3)
                     03                             # unsigned(3) / suit-common: /
                     58 84                          # bytes(132)
                        A2                          # map(2)
                           02                       # unsigned(2) / suit-components: /
                           81                       # array(1)
                              84                    # array(4)
                                 4B                 # bytes(11)
                                    544545502D446576696365 # "TEEP-Device"
                                 48                 # bytes(8)
                                    5365637572654653 # "SecureFS"
                                 50                 # bytes(16)
                                    8D82573A926D4754935332DC29997F74 # tc-uuid
                                 42                 # bytes(2)
                                    7461            # "ta"
                           04                       # unsigned(4) / suit-common-sequence: /
                           58 54                    # bytes(84)
                              86                    # array(6)
                                 14                 # unsigned(20) / suit-directive-override-parameters: /
                                 A4                 # map(4)
                                    01              # unsigned(1) / suit-parameter-vendor-identifier: /
                                    50              # bytes(16)
                                       C0DDD5F15243566087DB4F5B0AA26C2F
                                    02              # unsigned(2) / suit-parameter-class-identifier: /
                                    50              # bytes(16)
                                       DB42F7093D8C55BAA8C5265FC5820F4E
                                    03              # unsigned(3) / suit-parameter-image-digest: /
                                    58 24           # bytes(36)
                                       82           # array(2)
                                          2F        # negative(15) / -16 = suit-cose-alg-sha256 /
                                          58 20     # bytes(32)
                                             8CF71AC86AF31BE184EC7A05A411A8C3A14FD9B77A30D046397481469468ECE8
                                    0E              # unsigned(14) / suit-parameter-image-size: /
                                    14              # unsigned(20)
                                 01                 # unsigned(1) / suit-condition-vendor-identifier: /
                                 0F                 # unsigned(15)
                                 02                 # unsigned(2) / suit-condition-class-identifier: /
                                 0F                 # unsigned(15)
                     09                             # unsigned(9) / suit-install: /
                     4C                             # bytes(12)
                        86                          # array(6)
                           14                       # unsigned(20) / suit-directive-override-parameters: /
                           A1                       # map(1)
                              15                    # unsigned(21) / suit-parameter-uri: /
                              63                    # text(3)
                                 237463             # "#tc"
                           15                       # unsigned(21) / suit-directive-fetch: /
                           0F                       # unsigned(15)
                           03                       # unsigned(3) / suit-condition-image-match: /
                           0F                       # unsigned(15)
      03                                            # unsigned(3)
      58 FF                                         # bytes(255)
         A6                                         # map(6)
            01                                      # unsigned(1) / suit-manifest-version: /
            01                                      # unsigned(1)
            02                                      # unsigned(2) / suit-manifest-sequence-number: /
            03                                      # unsigned(3)
            03                                      # unsigned(3) / suit-common: /
            58 A7                                   # bytes(167)
               A3                                   # map(3)
                  01                                # unsigned(1)
                  81                                # array(1)
                     A1                             # map(1)
                        01                          # unsigned(1) / suit-dependency-digest: /
                        82                          # array(2)
                           2F                       # negative(15) / -16 = suit-cose-alg-sha256 /
                           58 20                    # bytes(32) / suit-digest-bytes: /
                              14A98BE957DE38FAE37376EA491FD6CAD9BFBD3C90051C8F5B017D7A496C3B05
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
                                 2F                 # negative(15) / -16 = suit-cose-alg-sha256 /
                                 58 20              # bytes(32)
                                    AAABCCCDEEEF00012223444566678889ABBBCDDDEFFF01112333455567778999
                           0E                       # unsigned(14) / suit-parameter-image-size: /
                           18 40                    # unsigned(64)
                        01                          # unsigned(1) / suit-condition-vendor-identifier: /
                        0F                          # unsigned(15)
                        02                          # unsigned(2) / suit-condition-class-identifier: /
                        0F                          # unsigned(15)
            07                                      # unsigned(7) / suit-dependency-resolution: /
               55                                   # bytes(21)
                  88                                # array(8)
                     0D                             # unsigned(13) / suit-directive-set-dependency-index: /
                     00                             # unsigned(0)
                     14                             # unsigned(20) / suit-directive-set-override-parameters: /
                     A1                             # map(1)
                        15                          # unsigned(21) / suit-parameter-uri: /
                        6A                          # text(10)
                           23646570656E64696E67     # "#depending"
                     15                             # unsigned(21) / suit-directive-fetch: /
                     02                             # unsigned(2)
                     03                             # unsigned(3) / suit-condition-image-match: /
                     0F                             # unsigned(15)
            09                                      # unsigned(9) / suit-install: /
            58 2F                                   # bytes(47)
               8C                                   # array(12)
                  0D                                # unsigned(13) / suit-directive-set-dependency-index: /
                  00                                # unsigned(0)
                  12                                # unsigned(18) / suit-directive-process-dependency: /
                  00                                # unsigned(0)
                  0C                                # unsigned(12) / suit-directive-set-component-index: /
                  00                                # unsigned(0)
                  14                                # unsigned(20) / suit-directive-override-parameters: /
                  A1                                # map(1)
                     15                             # unsigned(21) / suit-parameter-uri: /
                     78 1F                          # text(31)
                        68747470733A2F2F6578616D706C652E6F72672F636F6E6669672E6A736F6E # "https://example.org/config.json"
                  15                                # unsigned(21) / suit-directive-fetch: /
                  02                                # unsigned(2)
                  03                                # unsigned(3) / suit-condition-image-match: /
                  0F                                # unsigned(15)
            0A                                      # unsigned(10) / suit-validate: /
            45                                      # bytes(5)
               84                                   # array(4)
                  0C                                # unsigned(12) / suit-directive-set-component-index: /
                  00                                # unsigned(0)
                  03                                # unsigned(3) / suit-condition-image-match: /
                  0F                                # unsigned(15)
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
D86BA3025873825824822F5820844CA9D399193FB8BA987CBCD340D8F004
9640BEBAF8BB6FC06E1CAD10FD9179584AD28443A10126A0F658405028EE
BA1F5B1DCA1BBEEA62C1ED461BB9FEB6BBFD1A71BE06B8EDF226C298A41B
6CE4727CCB4E92788F5DA764C5CDE7E9D45E66091EBD33ECDCD2FFF6F713
ED6A23646570656E64696E6759012FD86BA3025873825824822F582014A9
8BE957DE38FAE37376EA491FD6CAD9BFBD3C90051C8F5B017D7A496C3B05
584AD28443A10126A0F658404093B323953785981EB607C8BA61B21E5C4F
85726A2AF48C1CB05BD4401B1B1565070728FDA38E6496D631E1D23F966C
FF7805EDE721D48507D9192993DA8722632374635448656C6C6F2C205365
6375726520576F726C642103589AA401010203035884A20281844B544545
502D446576696365485365637572654653508D82573A926D4754935332DC
29997F744274610458548614A40150C0DDD5F15243566087DB4F5B0AA26C
2F0250DB42F7093D8C55BAA8C5265FC5820F4E035824822F58208CF71AC8
6AF31BE184EC7A05A411A8C3A14FD9B77A30D046397481469468ECE80E14
010F020F094C8614A11563237463150F030F0358FFA6010102030358A7A3
0181A101822F582014A98BE957DE38FAE37376EA491FD6CAD9BFBD3C9005
1C8F5B017D7A496C3B050281834B544545502D4465766963654853656375
726546534B636F6E6669672E6A736F6E045857880C0014A40150C0DDD5F1
5243566087DB4F5B0AA26C2F0250DB42F7093D8C55BAA8C5265FC5820F4E
035824822F5820AAABCCCDEEEF00012223444566678889ABBBCDDDEFFF01
1123334555677789990E1840010F020F0755880D0014A1156A2364657065
6E64696E671502030F09582F8C0D0012000C0014A115781F68747470733A
2F2F6578616D706C652E6F72672F636F6E6669672E6A736F6E1502030F0A
45840C00030F
~~~~
