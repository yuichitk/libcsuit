
## Example 2: SUIT Manifest including the Trusted Component Binary {#suit-integrated}
{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
/ SUIT_Envelope = / 107({
  / authentication-wrapper / 2: << [
    / digest: / << [
      / algorithm-id: / -16 / SHA-256 /,
      / digest-bytes: / h'e8b5ec4510260b42b489fdec4b4918e8e97eb6e135c1b3b40e82419bf79224de'
    ] >>,
    / signatures: / << 18([
      / protected: / << {
        / alg / 1: -7 / ES256 /
      } >>,
      / unprotected: / {
      },
      / payload: / null,
      / signature: / h'c3c646030a93ec39e3f27111be73a2810a9f7a57bb34e9c9916fc0601eab8eb506b96c70864149664c1d090757714ace153fbb982dfda5b3fc150d89581e3994'
    ]) >>
  ] >>,
  / manifest / 3: << {
    / manifest-version / 1: 1,
    / manifest-sequence-number / 2: 3,
    / common / 3: << {
      / components / 2: [
        [h'544545502d446576696365', h'5365637572654653', h'8d82573a926d4754935332dc29997f74', h'7461']
      ],
      / common-sequence / 4: << [
        / directive-override-parameters / 20, {
          / vendor-id / 1: h'c0ddd5f15243566087db4f5b0aa26c2f' / c0ddd5f1-5243-5660-87db-4f5b0aa26c2f /,
          / class-id / 2: h'db42f7093d8c55baa8c5265fc5820f4e' / db42f709-3d8c-55ba-a8c5-265fc5820f4e /,
          / image-digest / 3: << [
            / algorithm-id: / -16 / SHA-256 /,
            / digest-bytes: / h'8cf71ac86af31be184ec7a05a411a8c3a14fd9b77a30d046397481469468ece8'
          ] >>,
          / image-size / 14: 20
        },
        / condition-vendor-identifier / 1, 15,
        / condition-class-identifier / 2, 15
      ] >>
    } >>,
    / install / 17: << [
      / directive-override-parameters / 20, {
        / uri / 21: "#tc"
      },
      / directive-fetch / 21, 15,
      / condition-image-match / 3, 15
    ] >>
  } >>,
  "#tc" : h'48656c6c6f2c2053656375726520576f726c6421'
})
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
d86ba3025873825824822f5820e8b5ec4510260b42b489fdec4b4918e8e9
7eb6e135c1b3b40e82419bf79224de584ad28443a10126a0f65840c3c646
030a93ec39e3f27111be73a2810a9f7a57bb34e9c9916fc0601eab8eb506
b96c70864149664c1d090757714ace153fbb982dfda5b3fc150d89581e39
9403589aa401010203035884a20281844b544545502d4465766963654853
65637572654653508d82573a926d4754935332dc29997f74427461045854
8614a40150c0ddd5f15243566087db4f5b0aa26c2f0250db42f7093d8c55
baa8c5265fc5820f4e035824822f58208cf71ac86af31be184ec7a05a411
a8c3a14fd9b77a30d046397481469468ece80e14010f020f114c8614a115
63237463150f030f632374635448656c6c6f2c2053656375726520576f72
6c6421
~~~~
