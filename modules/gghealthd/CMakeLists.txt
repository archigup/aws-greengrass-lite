# aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

ggl_init_module(
  gghealthd
  LIBS ggl-sdk
       ggl-common
       ggl-exec
       ggl-constants
       core-bus
       ggl-socket-server
       core-bus-gg-config
       PkgConfig::libsystemd)
