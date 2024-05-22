/* gravel - Utilities for AWS IoT Core clients
 * Copyright (C) 2024 Amazon.com, Inc. or its affiliates
 */

#include "args.h"
#include "gravel/object.h"
#include "gravel/server.h"
#include "mqtt.h"
#include <argp.h>

static char doc[] = "iotcored -- MQTT spooler for AWS IoT Core";

static struct argp_option opts[]
    = { { "endpoint", 'e', "address", 0, "AWS IoT Core endpoint", 0 },
        { "id", 'i', "name", 0, "MQTT client identifier", 0 },
        { "rootca", 'r', "path", 0, "Path to AWS IoT Core CA PEM", 0 },
        { "cert", 'c', "path", 0, "Path to client certificate", 0 },
        { "key", 'k', "path", 0, "Path to key for client certificate", 0 },
        { 0 } };

static error_t arg_parser(int key, char *arg, struct argp_state *state) {
    IotcoredArgs *args = state->input;
    switch (key) {
    case 'e': args->endpoint = arg; break;
    case 'i': args->id = arg; break;
    case 'r': args->rootca = arg; break;
    case 'c': args->cert = arg; break;
    case 'k': args->key = arg; break;
    case ARGP_KEY_END:
        if ((args->endpoint == NULL) || (args->id == NULL)
            || (args->rootca == NULL) || (args->cert == NULL)
            || (args->key == NULL)) {
            argp_usage(state);
        }
        break;
    default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { opts, arg_parser, 0, doc, 0, 0, 0 };

int main(int argc, char **argv) {
    IotcoredArgs args = { 0 };

    argp_parse(&argp, argc, argv, 0, 0, &args);

    int ret = iotcored_mqtt_connect(&args);

    if (ret != 0) return ret;

    gravel_listen(GRAVEL_STR("/aws/gravel/iotcored"), NULL);
}