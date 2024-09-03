// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#define _GNU_SOURCE

#include "database_helper.h"
#include "fleet-provisioning.h"
#include "generate_certificate.h"
#include "ggl/exec.h"
#include "provisioner.h"
#include <sys/types.h>
#include <fcntl.h>
#include <ggl/alloc.h>
#include <ggl/bump_alloc.h>
#include <ggl/error.h>
#include <ggl/file.h>
#include <ggl/log.h>
#include <ggl/object.h>
#include <ggl/vector.h>
#include <openssl/evp.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_PATH_LENGTH 4096
#define MAX_ENDPOINT_LENGTH 128
#define MAX_TEMPLATE_PARAMS_LEN 4096

static pid_t iotcored_pid = -1;

static void kill_iotcored(void) {
    exec_kill_process(iotcored_pid);
}

static GglError start_iotcored(FleetProvArgs *args) {
    char *iotcore_d_args[] = {
        args->iotcored_path,  "-n", "iotcoredfleet",       "-e",
        args->data_endpoint,  "-i", args->template_name,   "-r",
        args->root_ca_path,   "-c", args->claim_cert_path, "-k",
        args->claim_key_path,
    };

    GglError ret
        = exec_command_without_child_wait(iotcore_d_args, &iotcored_pid);
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    GGL_LOGD("fleet-provisioning", "PID for new iotcored: %d", iotcored_pid);

    atexit(kill_iotcored);

    return ret;
}

// TODO: refactor this
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static GglError fetch_from_db(FleetProvArgs *args) {
    if (args->claim_cert_path == NULL) {
        GGL_LOGD(
            "fleet-provisioning",
            "Requesting db for "
            "services/aws.greengrass.fleet_provisioning/configuration/"
            "claimCertPath."
        );

        static uint8_t claim_cert_path[MAX_PATH_LENGTH + 1] = { 0 };

        GglBuffer buf
            = { .data = claim_cert_path, .len = sizeof(claim_cert_path) - 1 };
        GglError ret = get_value_from_db(
            GGL_LIST(
                GGL_OBJ_STR("services"),
                GGL_OBJ_STR("aws.greengrass.fleet_provisioning"),
                GGL_OBJ_STR("configuration"),
                GGL_OBJ_STR("claimCertPath.")
            ),
            &buf
        );
        if (ret != GGL_ERR_OK) {
            return ret;
        }
        if (buf.len == 0) {
            GGL_LOGE(
                "fleet-provisioning",
                "Empty config value for "
                "services/aws.greengrass.fleet_provisioning/configuration/"
                "claimCertPath."
            );
            return GGL_ERR_FATAL;
        }

        buf.data[buf.len] = '\0';
        args->claim_cert_path = (char *) buf.data;
    }

    if (args->claim_key_path == NULL) {
        GGL_LOGD(
            "fleet-provisioning",
            "Requesting db for "
            "services/aws.greengrass.fleet_provisioning/configuration/"
            "claimKeyPath."
        );

        static uint8_t claim_key_path[MAX_PATH_LENGTH + 1] = { 0 };

        GglBuffer buf
            = { .data = claim_key_path, .len = sizeof(claim_key_path) - 1 };
        GglError ret = get_value_from_db(
            GGL_LIST(
                GGL_OBJ_STR("services"),
                GGL_OBJ_STR("aws.greengrass.fleet_provisioning"),
                GGL_OBJ_STR("configuration"),
                GGL_OBJ_STR("claimKeyPath.")
            ),
            &buf
        );
        if (ret != GGL_ERR_OK) {
            return ret;
        }
        if (buf.len == 0) {
            GGL_LOGE(
                "fleet-provisioning",
                "Empty config value for "
                "services/aws.greengrass.fleet_provisioning/configuration/"
                "claimKeyPath."
            );
            return GGL_ERR_FATAL;
        }

        buf.data[buf.len] = '\0';
        args->claim_key_path = (char *) buf.data;
    }

    if (args->root_ca_path == NULL) {
        GGL_LOGD("fleet-provisioning", "Requesting db for system/rootCaPath.");

        static uint8_t root_ca_path[MAX_PATH_LENGTH + 1] = { 0 };

        GglBuffer buf
            = { .data = root_ca_path, .len = sizeof(root_ca_path) - 1 };
        GglError ret = get_value_from_db(
            GGL_LIST(GGL_OBJ_STR("system"), GGL_OBJ_STR("rootCaPath")), &buf
        );
        if (ret != GGL_ERR_OK) {
            return ret;
        }
        if (buf.len == 0) {
            GGL_LOGE(
                "fleet-provisioning",
                "Empty config value for system/rootCaPath."
            );
            return GGL_ERR_FATAL;
        }

        buf.data[buf.len] = '\0';
        args->root_ca_path = (char *) buf.data;
    }

    if (args->data_endpoint == NULL) {
        GGL_LOGD(
            "fleet-provisioning",
            "Requesting db for "
            "services/aws.greengrass.fleet_provisioning/configuration/"
            "iotDataEndpoint."
        );

        static uint8_t data_endpoint[MAX_ENDPOINT_LENGTH + 1] = { 0 };

        GglBuffer buf
            = { .data = data_endpoint, .len = sizeof(data_endpoint) - 1 };
        GglError ret = get_value_from_db(
            GGL_LIST(
                GGL_OBJ_STR("services"),
                GGL_OBJ_STR("aws.greengrass.fleet_provisioning"),
                GGL_OBJ_STR("configuration"),
                GGL_OBJ_STR("iotDataEndpoint")
            ),
            &buf
        );
        if (ret != GGL_ERR_OK) {
            return ret;
        }
        if (buf.len == 0) {
            GGL_LOGE(
                "fleet-provisioning",
                "Empty config value for "
                "services/aws.greengrass.fleet_provisioning/configuration/"
                "iotDataEndpoint."
            );
            return GGL_ERR_FATAL;
        }

        buf.data[buf.len] = '\0';
        args->data_endpoint = (char *) buf.data;
    }

    if (args->template_name == NULL) {
        GGL_LOGD(
            "fleet-provisioning",
            "Requesting db for "
            "services/aws.greengrass.fleet_provisioning/configuration/"
            "templateName"
        );

        static uint8_t template_name[MAX_TEMPLATE_NAME_LEN + 1] = { 0 };

        GglBuffer buf
            = { .data = template_name, .len = sizeof(template_name) - 1 };
        GglError ret = get_value_from_db(
            GGL_LIST(
                GGL_OBJ_STR("services"),
                GGL_OBJ_STR("aws.greengrass.fleet_provisioning"),
                GGL_OBJ_STR("configuration"),
                GGL_OBJ_STR("templateName")
            ),
            &buf
        );
        if (ret != GGL_ERR_OK) {
            return ret;
        }
        if (buf.len == 0) {
            GGL_LOGE(
                "fleet-provisioning",
                "Empty config value for "
                "services/aws.greengrass.fleet_provisioning/configuration/"
                "templateName."
            );
            return GGL_ERR_FATAL;
        }

        buf.data[buf.len] = '\0';
        args->template_name = (char *) buf.data;
    }

    if (args->template_params == NULL) {
        GGL_LOGD(
            "fleet-provisioning",
            "Requesting db for "
            "services/aws.greengrass.fleet_provisioning/configuration/"
            "templateParams"
        );

        static uint8_t template_params[MAX_TEMPLATE_PARAMS_LEN + 1] = { 0 };

        GglBuffer buf
            = { .data = template_params, .len = sizeof(template_params) - 1 };
        GglError ret = get_value_from_db(
            GGL_LIST(
                GGL_OBJ_STR("services"),
                GGL_OBJ_STR("aws.greengrass.fleet_provisioning"),
                GGL_OBJ_STR("configuration"),
                GGL_OBJ_STR("templateParams")
            ),
            &buf
        );
        if (ret != GGL_ERR_OK) {
            return ret;
        }
        if (buf.len == 0) {
            GGL_LOGE(
                "fleet-provisioning",
                "Empty config value for "
                "services/aws.greengrass.fleet_provisioning/configuration/"
                "templateParams."
            );
            return GGL_ERR_FATAL;
        }

        args->template_params = (char *) buf.data;
    }

    return GGL_ERR_OK;
}

GglError run_fleet_prov(FleetProvArgs *args) {
    GglError ret = fetch_from_db(args);
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    static uint8_t root_path_buf[MAX_PATH_LENGTH] = { 0 };
    GglBuffer root_path = GGL_BUF(root_path_buf);

    GGL_LOGD("fleet-provisioning", "Requesting db for system/rootpath.");
    ret = get_value_from_db(
        GGL_LIST(GGL_OBJ_STR("system"), GGL_OBJ_STR("rootpath")), &root_path
    );
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    ret = start_iotcored(args);
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    int root_path_fd;
    ret = ggl_dir_open(root_path, O_PATH, &root_path_fd);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("fleet-provisioning", "Failed to open rootpath.");
        return ret;
    }

    generate_key_files(root_path_fd);

    GglByteVec path_vec = GGL_BYTE_VEC(root_path_buf);
    path_vec.buf = root_path;

    ret = ggl_byte_vec_append(&path_vec, GGL_STR("/private_key.pem"));
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("fleet-provisioning", "Failed to build key path.");
        return ret;
    }

    ret = save_value_to_db(
        GGL_LIST(GGL_OBJ_STR("system")),
        GGL_OBJ_MAP({ GGL_STR("privateKeyPath"), GGL_OBJ(path_vec.buf) })
    );
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    path_vec = GGL_BYTE_VEC(root_path_buf);
    path_vec.buf = root_path;

    ret = ggl_byte_vec_append(&path_vec, GGL_STR("/certificate.pem.crt"));
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("fleet-provisioning", "Failed to build key path.");
        return ret;
    }

    ret = save_value_to_db(
        GGL_LIST(GGL_OBJ_STR("system")),
        GGL_OBJ_MAP({ GGL_STR("certificateFilePath"), GGL_OBJ(path_vec.buf) })
    );
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    static char csr_buf[2048] = { 0 };
    FILE *fp;
    ulong file_size;

    // Open the file in binary mode
    fp = fopen("./csr.pem", "rb");
    if (fp == NULL) {
        perror("Error opening file");
        return 1;
    }

    // Get the file size
    fseek(fp, 0, SEEK_END);
    file_size = (ulong) ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Read the file into the buffer
    size_t read_size = fread(csr_buf, 1, file_size, fp);

    // Close the file
    fclose(fp);

    if (read_size != file_size) {
        GGL_LOGE("fleet-provisioning", "Failed to read th whole file.");
        return GGL_ERR_FAILURE;
    }

    GGL_LOGD(
        "fleet-provisioning",
        "New String: %.*s.",
        (int) strlen(csr_buf),
        csr_buf
    );

    ret = make_request(csr_buf, cert_file_path);

    if (ret != GGL_ERR_OK) {
        return ret;
    }

    return 0;
}
