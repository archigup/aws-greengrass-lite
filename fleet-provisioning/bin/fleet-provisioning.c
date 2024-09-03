// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#define _GNU_SOURCE

#include "fleet-provisioning.h"
#include <argp.h>
#include <ggl/error.h>
#include <ggl/log.h>
#include <ggl/object.h>
#include <ggl/vector.h>
#include <string.h>
#include <stdint.h>

static char doc[] = "fleet-provisioning -- Configure Greengrass with AWS IoT "
                    "Fleet Provisioning";

static struct argp_option opts[]
    = { { "claim-key",
          'k',
          "path",
          OPTION_ARG_OPTIONAL,
          "Path to key for claim certificate",
          0 },
        { "claim-cert", 'c', "path", 0, "Path to claim certificate", 0 },
        { "template-name",
          't',
          "name",
          OPTION_ARG_OPTIONAL,
          "AWS IoT Fleet Provisioning template name",
          0 },
        { "template-param",
          'p',
          "json",
          OPTION_ARG_OPTIONAL,
          "Additional template parameters",
          0 },
        { "data-endpoint",
          'e',
          "name",
          OPTION_ARG_OPTIONAL,
          "AWS IoT Core data endpoint",
          0 },
        { "root-ca-path",
          'r',
          "path",
          OPTION_ARG_OPTIONAL,
          "Path to AWS IoT Core CA PEM",
          0 },
        { 0 } };

static error_t arg_parser(int key, char *arg, struct argp_state *state) {
    FleetProvArgs *args = state->input;
    switch (key) {
    case 'c':
        args->claim_cert_path = arg;
        break;
    case 'k':
        args->claim_key_path = arg;
        break;
    case 't':
        args->template_name = arg;
        break;
    case 'p':
        args->template_parameters = arg;
        break;
    case 'e':
        args->data_endpoint = arg;
        break;
    case 'r':
        args->root_ca_path = arg;
        break;
    case ARGP_KEY_END:
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { opts, arg_parser, 0, doc, 0, 0, 0 };

// includes trailing slash if any (path searches become "")
static GglBuffer get_bin_path(char *argv0) {
    size_t len = strlen(argv0);
    char *slash = memrchr(argv0, '/', len);
    len = (slash == NULL) ? 0 : ((size_t) (slash - argv0) + 1);
    return (GglBuffer) { .data = (uint8_t *) argv0, .len = len };
}

int main(int argc, char **argv) {
    static FleetProvArgs args = { 0 };

    if (argc < 1) {
        return 1;
    }

    GglBuffer bin_path = get_bin_path(argv[0]);

    // TODO: properly size this buffer
    static char iotcored_path[1025] = { 0 };
    GglByteVec iotcored_path_vec = GGL_BYTE_VEC(iotcored_path);
    GglError ret = ggl_byte_vec_append(&iotcored_path_vec, bin_path);
    ggl_byte_vec_append_cont(&ret, &iotcored_path_vec, GGL_STR("iotcored"));
    ggl_byte_vec_push_cont(&ret, &iotcored_path_vec, '\0');
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("fleet-provisioning", "Failed to build iotcored path.");
        return 1;
    }

    // NOLINTNEXTLINE(concurrency-mt-unsafe)
    argp_parse(&argp, argc, argv, 0, 0, &args);
    args.iotcored_path = iotcored_path;

    ret = run_fleet_prov(&args);
    if (ret != GGL_ERR_OK) {
        return 1;
    }
}
