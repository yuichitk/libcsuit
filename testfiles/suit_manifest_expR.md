
## E.4. Example 4: Unlink a Trusted Component {#suit-unlink}
{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
/ SUIT_Envelope = / 107({
  / authentication-wrapper / 2: << [
    / digest: / << [
      / algorithm-id: / -16 / SHA-256 /,
      / digest-bytes: / h'54ea3d80aaf5370527e8c4fc9e0d91ff0bd0fed26aeab602ca516541fef7f15a'
    ] >>,
    / signatures: / << 18([
      / protected: / << {
        / alg / 1: -7 / ES256 /
      } >>,
      / unprotected: / {
      },
      / payload: / null,
      / signature: / h'436a36c33a3300d13acf0075ba751b419fe1e8ccab6cfb7952c2e97fd5da70278ea3d8a8377d247cf8fe7f2874df5a0f31b042c659a98dd57a0dc23f094666e8'
    ]) >>
  ] >>,
  / manifest / 3: << {
    / manifest-version / 1: 1,
    / manifest-sequence-number / 2: 18446744073709551615,
    / common / 3: << {
      / components / 2: [
        [h'544545502d446576696365', h'5365637572654653', h'8d82573a926d4754935332dc29997f74', h'7461']
      ],
      / common-sequence / 4: << [
        / directive-override-parameters / 20, {
          / vendor-id / 1: h'c0ddd5f15243566087db4f5b0aa26c2f' / c0ddd5f1-5243-5660-87db-4f5b0aa26c2f /,
          / class-id / 2: h'db42f7093d8c55baa8c5265fc5820f4e' / db42f709-3d8c-55ba-a8c5-265fc5820f4e /
        },
        / condition-vendor-identifier / 1, 15,
        / condition-class-identifier / 2, 15
      ] >>
    } >>,
    / install / 17: << [
      / directive-set-component-index / 12, 0,
      / directive-unlink / 33, 0
    ] >>
  } >>
})
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
d86ba2025873825824822f582054ea3d80aaf5370527e8c4fc9e0d91ff0b
d0fed26aeab602ca516541fef7f15a584ad28443a10126a0f65840436a36
c33a3300d13acf0075ba751b419fe1e8ccab6cfb7952c2e97fd5da70278e
a3d8a8377d247cf8fe7f2874df5a0f31b042c659a98dd57a0dc23f094666
e8035873a40101021bffffffffffffffff03585ba20281844b544545502d
446576696365485365637572654653508d82573a926d4754935332dc2999
7f7442746104582b8614a20150c0ddd5f15243566087db4f5b0aa26c2f02
50db42f7093d8c55baa8c5265fc5820f4e010f020f1146840c00182100
~~~~
