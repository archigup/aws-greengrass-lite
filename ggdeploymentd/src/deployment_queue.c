// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "deployment_queue.h"
#include "deployment_model.h"
#include <sys/types.h>
#include <assert.h>
#include <ggl/alloc.h>
#include <ggl/buffer.h>
#include <ggl/bump_alloc.h>
#include <ggl/cleanup.h>
#include <ggl/error.h>
#include <ggl/log.h>
#include <ggl/map.h>
#include <ggl/object.h>
#include <ggl/vector.h>
#include <pthread.h>
#include <string.h>
#include <uuid/uuid.h>
#include <stdbool.h>
#include <stdint.h>

#ifndef DEPLOYMENT_QUEUE_SIZE
#define DEPLOYMENT_QUEUE_SIZE 10
#endif

#ifndef DEPLOYMENT_MEM_SIZE
#define DEPLOYMENT_MEM_SIZE 5000
#endif

static GglDeployment deployments[DEPLOYMENT_QUEUE_SIZE];
static uint8_t deployment_mem[DEPLOYMENT_QUEUE_SIZE][DEPLOYMENT_MEM_SIZE];
static size_t queue_index = 0;
static size_t queue_count = 0;

static pthread_mutex_t queue_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t notify_cond = PTHREAD_COND_INITIALIZER;

static bool get_matching_deployment(GglBuffer deployment_id, size_t *index) {
    for (size_t i = 0; i < queue_count; i++) {
        size_t index_i = (queue_index + i) % DEPLOYMENT_QUEUE_SIZE;
        if (ggl_buffer_eq(deployment_id, deployments[index_i].deployment_id)) {
            *index = index_i;
            return true;
        }
    }
    return false;
}

static GglError null_terminate_buffer(GglBuffer *buf, GglAlloc *alloc) {
    if (buf->len == 0) {
        *buf = GGL_STR("");
        return GGL_ERR_OK;
    }

    uint8_t *mem = GGL_ALLOCN(alloc, uint8_t, buf->len + 1);
    if (mem == NULL) {
        GGL_LOGE("Failed to allocate memory for copying buffer.");
        return GGL_ERR_NOMEM;
    }

    memcpy(mem, buf->data, buf->len);
    mem[buf->len] = '\0';
    buf->data = mem;
    return GGL_ERR_OK;
}

static GglError deep_copy_deployment(
    GglDeployment *deployment, GglAlloc *alloc
) {
    assert(deployment != NULL);

    GglObject obj = GGL_OBJ_BUF(deployment->deployment_id);
    GglError ret = ggl_obj_deep_copy(&obj, alloc);
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    deployment->deployment_id = obj.buf;

    ret = null_terminate_buffer(&deployment->recipe_directory_path, alloc);
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    ret = null_terminate_buffer(&deployment->artifacts_directory_path, alloc);
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    obj = GGL_OBJ_MAP(deployment->root_component_versions_to_add);
    ret = ggl_obj_deep_copy(&obj, alloc);
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    deployment->root_component_versions_to_add = obj.map;

    obj = GGL_OBJ_MAP(deployment->cloud_root_components_to_add);
    ret = ggl_obj_deep_copy(&obj, alloc);
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    deployment->cloud_root_components_to_add = obj.map;

    obj = GGL_OBJ_LIST(deployment->root_components_to_remove);
    ret = ggl_obj_deep_copy(&obj, alloc);
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    deployment->root_components_to_remove = obj.list;

    obj = GGL_OBJ_MAP(deployment->component_to_configuration);
    ret = ggl_obj_deep_copy(&obj, alloc);
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    deployment->component_to_configuration = obj.map;

    obj = GGL_OBJ_BUF(deployment->configuration_arn);
    ret = ggl_obj_deep_copy(&obj, alloc);
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    deployment->configuration_arn = obj.buf;

    obj = GGL_OBJ_BUF(deployment->thing_group);
    ret = ggl_obj_deep_copy(&obj, alloc);
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    deployment->thing_group = obj.buf;

    return GGL_ERR_OK;
}

static void get_slash_and_colon_locations_from_arn(
    GglObject *arn, size_t *slash_index, size_t *last_colon_index
) {
    assert(*slash_index == 0);
    assert(*last_colon_index == 0);
    for (size_t i = arn->buf.len; i > 0; i--) {
        if (arn->buf.data[i - 1] == ':') {
            if (*last_colon_index == 0) {
                *last_colon_index = i - 1;
            }
        }
        if (arn->buf.data[i - 1] == '/') {
            *slash_index = i - 1;
        }
        if (*slash_index != 0 && *last_colon_index != 0) {
            break;
        }
    }
}

static GglError parse_deployment_obj(GglMap args, GglDeployment *doc) {
    *doc = (GglDeployment) { 0 };

    GglObject *recipe_directory_path;
    GglObject *artifacts_directory_path;
    GglObject *root_component_versions_to_add;
    GglObject *cloud_root_components_to_add;
    GglObject *root_components_to_remove;
    GglObject *component_to_configuration;
    GglObject *deployment_id;
    GglObject *configuration_arn;

    GglError ret = ggl_map_validate(
        args,
        GGL_MAP_SCHEMA(
            { GGL_STR("recipe_directory_path"),
              false,
              GGL_TYPE_BUF,
              &recipe_directory_path },
            { GGL_STR("artifacts_directory_path"),
              false,
              GGL_TYPE_BUF,
              &artifacts_directory_path },
            { GGL_STR("root_component_versions_to_add"),
              false,
              GGL_TYPE_MAP,
              &root_component_versions_to_add },
            { GGL_STR("components"),
              false,
              GGL_TYPE_MAP,
              &cloud_root_components_to_add },
            { GGL_STR("root_components_to_remove"),
              false,
              GGL_TYPE_LIST,
              &root_components_to_remove },
            { GGL_STR("component_to_configuration"),
              false,
              GGL_TYPE_MAP,
              &component_to_configuration },
            { GGL_STR("deployment_id"), false, GGL_TYPE_BUF, &deployment_id },
            { GGL_STR("configurationArn"),
              false,
              GGL_TYPE_BUF,
              &configuration_arn },
        )
    );
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Received invalid argument.");
        return GGL_ERR_INVALID;
    }

    if (recipe_directory_path != NULL) {
        doc->recipe_directory_path = recipe_directory_path->buf;
    }

    if (artifacts_directory_path != NULL) {
        doc->artifacts_directory_path = artifacts_directory_path->buf;
    }

    if (root_component_versions_to_add != NULL) {
        doc->root_component_versions_to_add
            = root_component_versions_to_add->map;
    }

    // TODO: Refactor. This is a cloud deployment doc only field.
    if (cloud_root_components_to_add != NULL) {
        doc->cloud_root_components_to_add = cloud_root_components_to_add->map;
    }

    if (root_components_to_remove != NULL) {
        doc->root_components_to_remove = root_components_to_remove->list;
    }

    if (component_to_configuration != NULL) {
        doc->component_to_configuration = component_to_configuration->map;
    }

    if (deployment_id != NULL) {
        doc->deployment_id = deployment_id->buf;
    } else {
        static uint8_t uuid_mem[37];
        uuid_t binuuid;
        uuid_generate_random(binuuid);
        uuid_unparse(binuuid, (char *) uuid_mem);
        doc->deployment_id = (GglBuffer) { .data = uuid_mem, .len = 36 };
    }

    if (configuration_arn != NULL) {
        // Assume that the arn has a version at the end, we want to discard the
        // version for the arn.
        size_t last_colon_index = 0;
        size_t slash_index = 0;
        get_slash_and_colon_locations_from_arn(
            configuration_arn, &slash_index, &last_colon_index
        );
        doc->configuration_arn
            = ggl_buffer_substr(configuration_arn->buf, 0, last_colon_index);
        doc->thing_group = ggl_buffer_substr(
            configuration_arn->buf, slash_index + 1, last_colon_index
        );
    } else {
        doc->thing_group = GGL_STR("LOCAL_DEPLOYMENTS");
    }

    return GGL_ERR_OK;
}

GglError ggl_deployment_enqueue(GglMap deployment_doc, GglByteVec *id) {
    GGL_MTX_SCOPE_GUARD(&queue_mtx);

    GglDeployment new = { 0 };
    GglError ret = parse_deployment_obj(deployment_doc, &new);
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    if (id != NULL) {
        ret = ggl_byte_vec_append(id, new.deployment_id);
        if (ret != GGL_ERR_OK) {
            GGL_LOGE("insufficient id length");
            return ret;
        }
    }

    new.state = GGL_DEPLOYMENT_QUEUED;

    size_t index;
    bool exists = get_matching_deployment(new.deployment_id, &index);
    if (exists) {
        if (deployments[index].state != GGL_DEPLOYMENT_QUEUED) {
            GGL_LOGI("Existing deployment not replaceable.");
            return GGL_ERR_FAILURE;
        }
        GGL_LOGI("Replacing existing deployment in queue.");
    } else {
        if (queue_count >= DEPLOYMENT_QUEUE_SIZE) {
            return GGL_ERR_BUSY;
        }

        GGL_LOGD("Adding a new deployment to the queue.");
        index = (queue_index + queue_count) % DEPLOYMENT_QUEUE_SIZE;
        queue_count += 1;
    }

    GglBumpAlloc balloc = ggl_bump_alloc_init(GGL_BUF(deployment_mem[index]));
    ret = deep_copy_deployment(&new, &balloc.alloc);
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    deployments[index] = new;

    pthread_cond_signal(&notify_cond);

    return GGL_ERR_OK;
}

GglError ggl_deployment_dequeue(GglDeployment **deployment) {
    GGL_MTX_SCOPE_GUARD(&queue_mtx);

    while (queue_count == 0) {
        pthread_cond_wait(&notify_cond, &queue_mtx);
    }

    deployments[queue_index].state = GGL_DEPLOYMENT_IN_PROGRESS;
    *deployment = &deployments[queue_index];

    GGL_LOGD("Set a deployment to in progress.");

    return GGL_ERR_OK;
}

void ggl_deployment_release(GglDeployment *deployment) {
    assert(deployment == &deployments[queue_index]);

    GGL_LOGD("Removing deployment from queue.");

    queue_count -= 1;
    queue_index = (queue_index + 1) % DEPLOYMENT_QUEUE_SIZE;
}
