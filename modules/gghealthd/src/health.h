// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef GGHEALTHD_HEALTH_H
#define GGHEALTHD_HEALTH_H

#include "ggl/error.h"
#include <ggl/buffer.h>

GglError gghealthd_init(void);

// get status from native orchestrator or local database
GglError gghealthd_get_status(GglBuffer component_name, GglBuffer *status);

// update status (with GG component lifecycle state) in
// native orchestrator or local database
GglError gghealthd_update_status(GglBuffer component_name, GglBuffer status);

GglError gghealthd_get_health(GglBuffer *status);

#endif
