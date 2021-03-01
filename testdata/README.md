# Testdata

Configuration files and keys for API tests should go here. Files have not
been added to the repository to avoid exposing keys and secrets.

The configuration file is a JSON file in the format, from the file 'sample_enc_conf.json'
in this directory:

    {
        "url": "https://emea.api.hvca.globalsign.com:8443/v2",
        "api_key": "api key goes here",
        "api_secret": "api secret goes here",
        "cert_file": "/home/jdoe/fully/qualified/path/to/certfile.pem",
        "key_file": "/home/jdoe/fully/qualified/path/to/keyfile.pem",
        "key_passphrase": "mypassphrase",
        "timeout": 5
    }

The "key_passphrase" field should be the empty string if the private key is not
encrypted.

To make the tests use your configuration file, you should name it "test_config.json".
