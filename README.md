# hvclient

[![GoDoc](https://godoc.org/github.com/globalsign/hvclient?status.svg)](https://godoc.org/github.com/globalsign/hvclient)
[![Build Status](https://github.com/globalsign/hvclient/actions/workflows/go.yml/badge.svg)](https://github.com/globalsign/hvclient/actions/workflows/go.yml)

Package hvclient provides an interface to the [GlobalSign Atlas Certificate
Management API](https://www.globalsign.com/en/resources/apis/api-documentation/globalsign_atlas_certificate_management_api.html).

## Installation

```
go get github.com/globalsign/hvclient
```

The `cmd/hvclient` directory contains a command line interface utility.

## Quickstart Guide

Basic usage is straightforward:

1. Create a `Client` object

2. Use it to make HVCA API calls.

Creating a `Client` object requires:

1. An API key and API secret provided by GlobalSign during account set-up; and

2. A private key and a certificate to use for mutual TLS authentication
   with the HVCA server. The private key should be the one associated with
   the public key that was provided to GlobalSign during account set-up, and
   the certificate should be the one provided by GlobalSign along with the API
   key and API secret.

The `Client` object may be created with either:

1. A [configuration file](#configuration-file), useful when the account credentials are located in
   files; or with

2. A `Config` object, useful when the account credentials are obtained
   programmatically from a secrets vault, from environment variables, or in some
   other manner.

## Configuration file

An example configuration file:

```
{
    "url": "https://emea.api.hvca.globalsign.com:8443/v2",
    "api_key": "<your_api_key>",
    "api_secret": "<your_api_secret>",
    "cert_file": "testdata/mtls_cert.pem",
    "key_file": "testdata/mtls_private_key.pem",
    "key_passphrase": "strongpassword",
    "insecure_skip_verify": false,
    "extra_headers": [
        "Header-Name-One": "value",
        "Header-Name-Two": "value"
    ],
    "timeout": 60
}
```

- `key_passphrase` must be provided if the mTLS private key is an encrypted
  PEM block as specified in RFC 1423.
- `insecure_skip_verify` controls whether the client verifies the server's
  certificate chain and host name. If true, any certificate presented by the
  server and any host name in that certificate is accepted. In this mode, TLS
  is susceptible to machine-in-the-middle attacks unless custom verification
  is used. This should be used only for testing.
- `extra_headers` are optional additional HTTP headers to include in the
  requests to the server.
- `timeout` specifies a request timeout in seconds.

## Demo

[![asciicast](https://asciinema.org/a/P6MSC1Qqe78GYWsiucs5DAM8B.svg)](https://asciinema.org/a/P6MSC1Qqe78GYWsiucs5DAM8B)
