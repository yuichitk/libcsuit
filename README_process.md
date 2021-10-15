# SUIT Manifest Processor
This feature interprets the SUIT manifest binary and then executes appropriate process.  
The caller can specify the callback functions, such as fetch, copy, etc.  
There is a sample application, `suit_manifest_process`, so that you can test it.  

## How to Test: Sample Result
```
$ make -f Makefile.process
$ ./suit_manifest_process ./testfiles/suit_manifest_exp1.cbor

main : Read public key from DER file.
048496811aae0baaabd26157189eecda26beaa8bf11b6f3fe6e2b5659c85dbc0ad3b1f2a4b6c098131c0a36dacd1d78bd381dcdfb09c052db33991db7338b4a896
044d5e5f3367ec6e411f0ec397452ac02e6541b212761314548a629379264c5a44308aeffc285e452ede343c0f35d21e0e2d3751f8bd32496f90af264d686ecded

main : Read Manifest file.

main : Decode Manifest file.
fetch callback : {
  uri : "http://example.com/file.bin" (27)
  dst-component-identifier : [0x00 , ]
  ptr : 0x7ffd238b6110 (34768)
  suit_report_t : RecPass0 RecFail1 SysPass0 SysFail0
}
```

## Sample Input SUIT Manifest Summary
```
+-testfiles/suit_manifest_exp1.cbor-----------+
| SUIT_Envelope {                             |
|   authentication-wrapper: [                 |
|     digest(manifest),                       |
|     COSE_Sign1(digest(manifest))            |
|   ],                                        |
|   manifest: {                               |
|     common: {                               |
|       common-sequence: [                    |
|         set-parameters: {                   |
|           image-size: 20,                   |
|           image-digest: digest(image)       |
|         }                                   |
|       ]                                     |
|     },                                      |
|     install: [                              |
|       set-parameters: {                     |
|         uri: "http://example.con/file.bin"  |
|       },                                    |
|       directive-fetch,                      |
|       condition-image-match                 |
|     ]                                       |
|   }                                         |
| }                                           |
+---------------------------------------------+
```

## Program Flow in Pseudocode
```
+-examples/suit_manifest_process_main.c--------+
| main() {                                     |
|   keys = prepare_keys();                     |
|   callbacks.fetch = fetch_callback;          |
|   m = get_manifest();                        |    +-libcsuit---------------------------------------+
|   suit_process_envelope(keys, m, callbacks); |===>| suit_process_envelope(keys, m, callbacks) {    |
| }                                            |    |   t = check_digest_and_extract(keys, m);       |
|                                              |    |   dependency_resolution(t);                    |
|                                              |    |   install(m.install) {                         |
| fetch_callback(uri, buf, report) {           |<===|     err = callbacks.fetch(t.uri, buf, report); |
|   err = get_image(uri, buf);                 |    |                                                |
|   suit_report(report, err);                  |    |                                                |
|   return SUIT_SUCCESS;                       |===>|     if (!err)                                  |
| }                                            |    |       callbacks.on_error(err, report);         |
|                                              |    |     err = check_image_digest(t.idigest, ptr);  |
| error_callback(err, report) {                |    |     if (!err)                                  |
|   // error-recovery                          |    |       callbacks.on_error(err, report);         |
|   if (fatal)                                 |    |   }                                            |
|     exit(EXIT_FAILURE);                      |    | }                                              |
|   return SUIT_SUCCESS;                       |    +------------------------------------------------+
| }                                            |
+----------------------------------------------+
```

