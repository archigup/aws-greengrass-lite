// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#define _GNU_SOURCE

#include "generate_certificate.h"
#include <errno.h>
#include <fcntl.h>
#include <ggl/defer.h>
#include <ggl/error.h>
#include <ggl/file.h>
#include <ggl/log.h>
#include <ggl/object.h>
#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdio.h>

// TODO: This should be 4096 if supported by IoT core
#define RSA_KEY_LENGTH 2048

GGL_DEFINE_DEFER(
    EVP_PKEY_CTX_free, EVP_PKEY_CTX *, ctx, EVP_PKEY_CTX_free(*ctx)
)
GGL_DEFINE_DEFER(EVP_PKEY_free, EVP_PKEY *, pkey, EVP_PKEY_free(*pkey));
GGL_DEFINE_DEFER(X509_REQ_free, X509_REQ *, pkey, X509_REQ_free(*pkey));

static GglError generate_keys(EVP_PKEY **pkey) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL) {
        GGL_LOGE("fleet-provisioning", "Error creating context.");
        return GGL_ERR_FAILURE;
    }
    GGL_DEFER(EVP_PKEY_CTX_free, ctx);

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        GGL_LOGE("fleet-provisioning", "Error initializing keygen.");
        return GGL_ERR_FAILURE;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_LENGTH) <= 0) {
        GGL_LOGE("fleet-provisioning", "Error setting RSA keygen bits.");
        return GGL_ERR_FAILURE;
    }

    if (EVP_PKEY_keygen(ctx, pkey) <= 0) {
        GGL_LOGE("fleet-provisioning", "Error generating RSA key.");
        return GGL_ERR_FAILURE;
    }

    return GGL_ERR_OK;
}

static X509_REQ *generate_csr(EVP_PKEY *pkey) {
    X509_REQ *req = X509_REQ_new();
    X509_REQ_set_version(req, 1);

    // TODO: This should just use Thing name
    X509_NAME *name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(
        name, "C", MBSTRING_ASC, (unsigned char *) "US", -1, -1, 0
    );
    X509_NAME_add_entry_by_txt(
        name, "ST", MBSTRING_ASC, (unsigned char *) "Washington", -1, -1, 0
    );
    X509_NAME_add_entry_by_txt(
        name, "L", MBSTRING_ASC, (unsigned char *) "Seattle", -1, -1, 0
    );
    X509_NAME_add_entry_by_txt(
        name, "O", MBSTRING_ASC, (unsigned char *) "Amazon", -1, -1, 0
    );
    X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC, (unsigned char *) "amazon.com", -1, -1, 0
    );
    X509_REQ_set_subject_name(req, name);

    X509_REQ_set_pubkey(req, pkey);
    X509_REQ_sign(req, pkey, EVP_sha256());

    X509_NAME_free(name);

    return req;
}

GglError generate_key_files(int root_path_fd) {
    OpenSSL_add_all_algorithms();
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

    EVP_PKEY *pkey = NULL;
    GglError ret = generate_keys(&pkey);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("fleet-provisioning", "Failed to Generate Certificate");
        return ret;
    }
    GGL_DEFER(EVP_PKEY_free, pkey);

    int fd;

    // Save private key
    fd = openat(
        root_path_fd,
        "private_key.pem",
        O_CLOEXEC | O_WRONLY | O_CREAT,
        S_IRUSR | S_IWUSR
    );
    if (fd < 0) {
        int err = errno;
        GGL_LOGE(
            "fleet-provisioning",
            "Err %d while opening %s.",
            err,
            "private_key.pem"
        );
        return GGL_ERR_FAILURE;
    }
    FILE *pkey_file = fdopen(fd, "wb");
    PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(pkey_file);

    // Save public key
    fd = openat(
        root_path_fd,
        "public_key.pem",
        O_CLOEXEC | O_WRONLY | O_CREAT,
        S_IRUSR | S_IWUSR
    );
    if (fd < 0) {
        int err = errno;
        GGL_LOGE(
            "fleet-provisioning",
            "Err %d while opening %s.",
            err,
            "public_key.pem"
        );
        return GGL_ERR_FAILURE;
    }
    FILE *pubkey_file = fdopen(fd, "wb");
    PEM_write_PUBKEY(pubkey_file, pkey);
    fclose(pubkey_file);

    X509_REQ *req = generate_csr(pkey);
    GGL_DEFER(X509_REQ_free, req);

    // Save CSR
    fd = openat(
        root_path_fd,
        "csr.pem",
        O_CLOEXEC | O_WRONLY | O_CREAT,
        S_IRUSR | S_IWUSR
    );
    if (fd < 0) {
        int err = errno;
        GGL_LOGE(
            "fleet-provisioning", "Err %d while opening %s.", err, "csr.pem"
        );
        return GGL_ERR_FAILURE;
    }
    FILE *csr_file = fdopen(fd, "wb");
    PEM_write_X509_REQ(csr_file, req);
    fclose(csr_file);

    return GGL_ERR_OK;
}
