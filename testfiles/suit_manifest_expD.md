
## Example 3: Supplying Personalization Data for Trusted Component Binary {#suit-personalization}
{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
/ SUIT_Envelope = / 107({
  / authentication-wrapper / 2: << [
    / digest: / << [
      / algorithm-id: / -16 / SHA-256 /,
      / digest-bytes: / h'b2967c80d2da2c9c226331ac4cf4c147f1d9e059c4eb6d165ab43e4c86275b9c'
    ] >>,
    / signatures: / << 18([
      / protected: / << {
        / alg / 1: -7 / ES256 /
      } >>,
      / unprotected: / {
      },
      / payload: / null,
      / signature: / h'be370c83aaf922a2d2a807d068879ee3d1f1781750181eee0251e96d320356b6e6d9553b9e33e4d250c52bcd446272f22a00af6f3c43daa7f263ef375307f646'
    ]) >>
  ] >>,
  / manifest / 3: << {
    / manifest-version / 1: 1,
    / manifest-sequence-number / 2: 3,
    / common / 3: << {
      / dependencies / 1: [
        / dependency-digest / 1: [
          / algorithm-id: / -16 / SHA-256 /,
          / digest-bytes: / h'549b1bf2e6f662167342a91e2cd16a695be2ecfb7c325639189d0ea8eba57d0a'
        ]
      ],
      / components / 2: [
        [h'544545502d446576696365', h'5365637572654653', h'636f6e6669672e6a736f6e']
      ],
      / common-sequence / 4: << [
        / directive-set-component-index / 12, 0,
        / directive-override-parameters / 20, {
          / vendor-id / 1: h'c0ddd5f15243566087db4f5b0aa26c2f' / c0ddd5f1-5243-5660-87db-4f5b0aa26c2f /,
          / class-id / 2: h'db42f7093d8c55baa8c5265fc5820f4e' / db42f709-3d8c-55ba-a8c5-265fc5820f4e /,
          / image-digest / 3: << [
            / algorithm-id: / -16 / SHA-256 /,
            / digest-bytes: / h'aaabcccdeeef00012223444566678889abbbcdddefff01112333455567778999'
          ] >>,
          / image-size / 14: 64
        },
        / condition-vendor-identifier / 1, 15,
        / condition-class-identifier / 2, 15
      ] >>
    } >>,
    / validate / 7: << [
      / directive-set-component-index / 12, 0,
      / condition-image-match / 3, 15
    ] >>,
    / dependency-resolution / 15: << [
      / directive-set-dependency-index / 13, 0,
      / directive-override-parameters / 20, {
        / uri / 21: "https://example.org/8d82573a-926d-4754-9353-32dc29997f74.suit"
      },
      / directive-fetch / 21, 2,
      / condition-image-match / 3, 15
    ] >>,
    / install / 17: << [
      / directive-set-dependency-index / 13, 0,
      / directive-process-dependency / 18, 0,
      / directive-set-component-index / 12, 0,
      / directive-override-parameters / 20, {
        / uri / 21: "https://example.org/config.json"
      },
      / directive-fetch / 21, 2,
      / condition-image-match / 3, 15
    ] >>
  } >>
})
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
d86ba2025873825824822f5820b2967c80d2da2c9c226331ac4cf4c147f1
d9e059c4eb6d165ab43e4c86275b9c584ad28443a10126a0f65840be370c
83aaf922a2d2a807d068879ee3d1f1781750181eee0251e96d320356b6e6
d9553b9e33e4d250c52bcd446272f22a00af6f3c43daa7f263ef375307f6
4603590134a6010102030358a7a30181a101822f5820549b1bf2e6f66216
7342a91e2cd16a695be2ecfb7c325639189d0ea8eba57d0a0281834b5445
45502d4465766963654853656375726546534b636f6e6669672e6a736f6e
045857880c0014a40150c0ddd5f15243566087db4f5b0aa26c2f0250db42
f7093d8c55baa8c5265fc5820f4e035824822f5820aaabcccdeeef000122
23444566678889abbbcdddefff011123334555677789990e1840010f020f
0745840c00030f0f5849880d0014a115783d68747470733a2f2f6578616d
706c652e6f72672f38643832353733612d393236642d343735342d393335
332d3332646332393939376637342e737569741502030f11582f8c0d0012
000c0014a115781f68747470733a2f2f6578616d706c652e6f72672f636f
6e6669672e6a736f6e1502030f
~~~~
