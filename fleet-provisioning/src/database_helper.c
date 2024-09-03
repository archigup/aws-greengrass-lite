// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "database_helper.h"
#include "ggl/error.h"
#include <ggl/alloc.h>
#include <ggl/bump_alloc.h>
#include <ggl/core_bus/client.h>
#include <ggl/log.h>
#include <ggl/object.h>
#include <string.h>
#include <stdint.h>

#define MAX_WRITE_BUFFER_SIZE 10000
static GglBuffer config_server = GGL_STR("/aws/ggl/ggconfigd");

GglError get_value_from_db(GglList key_path, GglBuffer *value) {
    GglMap params = GGL_MAP({ GGL_STR("key_path"), GGL_OBJ(key_path) }, );
    GglObject result;
    GglBumpAlloc alloc = ggl_bump_alloc_init(*value);

    GglError ret = ggl_call(
        config_server, GGL_STR("read"), params, NULL, &alloc.alloc, &result
    );
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("database-helper", "Read failed. Error %d", ret);
        return ret;
    }
    if (result.type != GGL_TYPE_BUF) {
        GGL_LOGE("database-helper", "Result is not a string");
        return GGL_ERR_CONFIG;
    }
    GGL_LOGI(
        "database-helper",
        "read value: %.*s",
        (int) result.buf.len,
        (char *) result.buf.data
    );
    *value = result.buf;
    return GGL_ERR_OK;
}

GglError save_value_to_db(GglList key_path, GglObject value) {
    static uint8_t big_buffer_transfer_for_bump[MAX_WRITE_BUFFER_SIZE] = { 0 };

    GglBumpAlloc the_allocator
        = ggl_bump_alloc_init(GGL_BUF(big_buffer_transfer_for_bump));

    GglMap params = GGL_MAP(
        { GGL_STR("key_path"), GGL_OBJ(key_path) },
        { GGL_STR("value"), value },
        { GGL_STR("timeStamp"), GGL_OBJ_I64(1723142212) }
    );
    GglObject result;

    GglError error = ggl_call(
        config_server,
        GGL_STR("write"),
        params,
        NULL,
        &the_allocator.alloc,
        &result
    );
    if (error != GGL_ERR_OK) {
        GGL_LOGE("database-helper", "insert failure");
        return error;
    }

    return GGL_ERR_OK;
}
