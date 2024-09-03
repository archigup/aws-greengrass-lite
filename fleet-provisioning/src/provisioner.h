// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef PROVISIONER_H
#define PROVISIONER_H

#include <sys/types.h>
#include <ggl/error.h>

// https://docs.aws.amazon.com/iot/latest/apireference/API_DescribeProvisioningTemplate.html
#define MAX_TEMPLATE_NAME_LEN 36

GglError make_request(char *csr_as_string, int root_path_fd);

#endif
