// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef FLEET_PROV_GENERATE_CERTIFICATE_H
#define FLEET_PROV_GENERATE_CERTIFICATE_H

#include <ggl/error.h>

GglError generate_key_files(int root_path_fd);

#endif
