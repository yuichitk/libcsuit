cmake_minimum_required(VERSION 3.10.2)
project(libcsuit
	DESCRIPTION "SUIT Manifest"
	LANGUAGES C
	VERSION 1.0.0)

set(CMAKE_C_FLAGS "-Wall -O3 -pedantic")
set(CMAKE_C_FLAGS_DEBUG "-Wall -O0 -g -DDEBUG") # use `-DCMAKE_BUILD_TYPE=Debug'

if(MBEDTLS)

	option(USE_PKCS11_HELPER_LIBRARY "Build mbed TLS with the pkcs11-helper library." OFF)
	option(ENABLE_ZLIB_SUPPORT "Build mbed TLS with zlib library." OFF)
	option(ENABLE_PROGRAMS "Build mbed TLS programs." OFF)
	option(ENABLE_TESTING "Build mbed TLS tests." OFF)

	set(CMAKE_INSTALL_NAME_DIR ${CMAKE_INSTALL_FULL_LIBDIR}/lib)
	include_directories(../mbedtls/include)

	# Use custom config file for Mbed TLS
	add_definitions(-DMBEDTLS_CONFIG_FILE="${CMAKE_SOURCE_DIR}/mbedtls_config.h")

	option(USE_STATIC_MBEDTLS_LIBRARY "Build mbed TLS static library." off)
	option(USE_SHARED_MBEDTLS_LIBRARY "Build mbed TLS shared library." on)

	if (CMAKE_SYSTEM MATCHES "OpenBSD")
		option(LINK_WITH_PTHREAD "Explicitly link mbed TLS library to pthread." on)
	endif()

	set(MBEDTLS_LIBRARIES "mbedtls") #  "mbedx509" "mbedcrypto"

	add_subdirectory(../mbedtls mbedtls)

	include_directories(../QCBOR/inc/)

	add_subdirectory(../QCBOR qcbor)

	set(QCBOR_LIBRARY "qcbor")

	add_definitions(-DMBEDTLS=1)

	add_subdirectory(../t_cose t_cose)

	set(T_COSE_LIBRARY "t_cose")

	include_directories(../QCBOR/inc/)
	include_directories(../t_cose/inc)
	include_directories(../t_cose/src)
	include_directories(examples/inc)
	include_directories(inc)

	# Compile code for use with the PSA Crypto API
	add_definitions(-DLIBCSUIT_PSA_CRYPTO_C=1)

	set(SOURCE_DECODE
		src/suit_common.c
		src/suit_digest.c
		src/suit_cose.c
		src/suit_manifest_print.c
		src/suit_manifest_encode.c
		src/suit_manifest_decode.c
		examples/suit_examples_common.c
		examples/suit_manifest_parser_main_psa.c
	)

	set(SOURCE_ENCODE
		src/suit_common.c
		src/suit_digest.c
		src/suit_cose.c
		src/suit_manifest_print.c
		src/suit_manifest_encode.c
		src/suit_manifest_decode.c
		examples/suit_examples_common.c
		examples/suit_manifest_encode_main_psa.c
	)

	add_executable(suit_manifest_parser_main_psa ${SOURCE_DECODE})

	add_executable(suit_manifest_encode_main_psa ${SOURCE_ENCODE})

	target_link_libraries(suit_manifest_parser_main_psa ${MBEDTLS_LIBRARIES} ${QCBOR_LIBRARY} ${T_COSE_LIBRARY} -lm)
	set_target_properties(suit_manifest_parser_main_psa PROPERTIES INSTALL_RPATH mbedtls t_cose qcbor)

	target_link_libraries(suit_manifest_encode_main_psa ${MBEDTLS_LIBRARIES} ${QCBOR_LIBRARY} ${T_COSE_LIBRARY} -lm)
	set_target_properties(suit_manifest_encode_main_psa PROPERTIES INSTALL_RPATH mbedtls t_cose qcbor)


else()

	include_directories(../QCBOR/inc/)
	include_directories(../t_cose/inc)
	include_directories(../t_cose/src)
	include_directories(examples/inc)
	include_directories(inc)


	add_subdirectory(../QCBOR qcbor)

	set(QCBOR_LIBRARY "qcbor")

	add_subdirectory(../t_cose t_cose)

	set(T_COSE_LIBRARY "t_cose")

	set(SOURCE_DECODE
		src/suit_common.c
		src/suit_digest.c
		src/suit_cose.c
		src/suit_manifest_print.c
		src/suit_manifest_encode.c
		src/suit_manifest_decode.c
		examples/suit_examples_common.c
		examples/suit_examples_cose.c	
		examples/suit_manifest_parser_main.c
	)

	add_executable(suit_manifest_parser_main ${SOURCE_DECODE})

	target_link_libraries(suit_manifest_parser_main -lcrypto ${QCBOR_LIBRARY} ${T_COSE_LIBRARY} -lm)
	set_target_properties(suit_manifest_parser_main PROPERTIES INSTALL_RPATH crypto t_cose qcbor)


	set(SOURCE_ENCODE
		src/suit_common.c
		src/suit_digest.c
		src/suit_cose.c
		src/suit_manifest_print.c
		src/suit_manifest_encode.c
		src/suit_manifest_decode.c
		examples/suit_examples_common.c
		examples/suit_examples_cose.c	
		examples/suit_manifest_encode_main.c
	)

	add_executable(suit_manifest_encode_main ${SOURCE_ENCODE})

	target_link_libraries(suit_manifest_encode_main -lcrypto ${QCBOR_LIBRARY} ${T_COSE_LIBRARY} -lm)
	set_target_properties(suit_manifest_encode_main PROPERTIES INSTALL_RPATH crypto t_cose qcbor)

endif()


