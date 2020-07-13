/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef SUIT_MANIFEST_PRINT_H
#define SUIT_MANIFEST_PRINT_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "qcbor/qcbor.h"
#include "suit_manifest_data.h"

#define MAX_PRINT_BYTE_COUNT       5

void suit_print_envelope(const suit_envelope_t *envelope);

#endif  /* SUIT_MANIFEST_PRINT_H */
