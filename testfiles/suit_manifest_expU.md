
## Example 1: SUIT Manifest pointing to URI of the Trusted Component Binary {#suit-uri}
{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
/ SUIT_Envelope = / 107({
  / authentication-wrapper / 2: << [
    / digest: / << [
      / algorithm-id: / -16 / SHA-256 /,
      / digest-bytes: / h'549b1bf2e6f662167342a91e2cd16a695be2ecfb7c325639189d0ea8eba57d0a'
    ] >>,
    / signatures: / << 18([
      / protected: / << {
        / alg / 1: -7 / ES256 /
      } >>,
      / unprotected: / {
      },
      / payload: / null,
      / signature: / h'478c87a8abb1f0388c8541c8396b268c72dbc8dff7aa34357e2a022741287d16df92be53e135a2daecf95800a623801705034d8187bb15de36a7d1dde37b5b7c'
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
        / uri / 21: "https://example.org/8d82573a-926d-4754-9353-32dc29997f74.ta"
      },
      / directive-fetch / 21, 15,
      / condition-image-match / 3, 15
    ] >>
  } >>
})
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
d86ba2025873825824822f5820549b1bf2e6f662167342a91e2cd16a695b
e2ecfb7c325639189d0ea8eba57d0a584ad28443a10126a0f65840478c87
a8abb1f0388c8541c8396b268c72dbc8dff7aa34357e2a022741287d16df
92be53e135a2daecf95800a623801705034d8187bb15de36a7d1dde37b5b
7c0358d4a401010203035884a20281844b544545502d4465766963654853
65637572654653508d82573a926d4754935332dc29997f74427461045854
8614a40150c0ddd5f15243566087db4f5b0aa26c2f0250db42f7093d8c55
baa8c5265fc5820f4e035824822f58208cf71ac86af31be184ec7a05a411
a8c3a14fd9b77a30d046397481469468ece80e14010f020f1158458614a1
15783b68747470733a2f2f6578616d706c652e6f72672f38643832353733
612d393236642d343735342d393335332d3332646332393939376637342e
7461150f030f
~~~~
