/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

/*
Package config contains functionality for extracting configuration
options from a JSON-encoded configuration file.

The configuration file should conform to the following format:

    {
        "hvca_url": "https://emea.api.hvca.globalsign.com:8443",
        "hvca_version": "v2",
        "api_key": "9999999999999999",
        "api_secret": "ffffffffffffffffffffffffffffffffffffffff",
        "cert_file": "/fully/qualified/path/to/tls/certificate.pem",
        "key_file": "/fully/qualified/path/to/tls/key.pem",
        "key_passphrase": "my_secret_passphrase",
        "timeout": 5
    }
*/
package config
