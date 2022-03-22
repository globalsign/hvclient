# hvclient

**hvclient** is a simple command line utility to:

 * demonstrate the use of the HVCA client library; 
 * provide a convenient command line interface to the HVCA system; and to
 * provide a convenient way to integrate HVCA API calls into client systems,
 as the command line utility can be called from scripts or other programs.


## Installation

If the **hvclient** and library are made publicly available on a github.com
repo, installation will be more straightforward, but for the moment a bit
of manual installation is necessary.

Go imports packages via a path beginning at a fixed location, or at one of
a finite set of fixed locations, so it is important to extract the files to
the correct location. 

At any time, Go looks for source code in a directory tree beginning at the
path specified in the `$GOPATH` environment variable. If this environment
variable is not set, it defaults to `$HOME/go`. The folder specified by
`$GOPATH` should have three subdirectories: `bin`, `pkg`, and `src`. The
first installation task (presuming you already have a working Go installation)
is to find out where your `$GOPATH` is.

The examples below assume a UNIX-like terminal environment.

An example where `$GOPATH` is not set:

    jdoe@host:~$ echo $GOPATH

    jdoe@host:~$ echo $HOME
    /home/jdoe
    jdoe@host:~$ ls /home/jdoe/go
    bin pkg src
    jdoe@host:~$ 

An example where `$GOPATH` is set:

    jdoe@host:~$ echo $GOPATH
    /home/jdoe/src/go
    jdoe@host:~$ ls /home/jdoe/src/go
    bin pkg src
    jdoe@host:~$ 

The **hvclient** repo should be extracted into the folder
`$GOPATH/src/globalsign/hvclient`. If this folder does not exist, you can
create it manually:

    jdoe@host:~$ echo $GOPATH
    /home/jdoe/src/go
    jdoe@host:~$ ls /home/jdoe/src/go
    bin pkg src
    jdoe@host:~$ cd /home/jdoe/src/go/src
    jdoe@host:src$ ls
    jdoe@host:src$ mkdir globalsign
    jdoe@host:src$ cd globalsign
    jdoe@host:globalsign$ mkdir hvclient
    jdoe@host:globalsign$ cd hvclient
    jdoe@host:hvclient$ pwd
    /home/jdoe/src/go/src/globalsign/hvclient
    jdoe@host:hvclient$

Having created this directory, you should extract the repository files into
it. You should then navigate to the `cmd/hvclient` directory and run
`go install`:

    jdoe@host:hvclient$ cd cmd/hvclient
    jdoe@host:hvclient$ pwd
    /home/jdoe/src/go/src/globalsign/hvclient/cmd/hvclient
    jdoe@host:hvclient$ go install
    jdoe@host:hvclient$

You can verify that the **hvclient** utility was correctly installed into
`$GOPATH/bin`:

    jdoe@host:hvclient$ ls /home/jdoe/src/go/bin
    hvclient
    jdoe@host:hvclient$

If `$GOPATH/bin` is already in your `$PATH`, then you should now be able to
run **hvclient**:

    jdoe@host:hvclient$ hvclient -h
    Usage of hvclient:
      -certsexpiring
            certificates expiring during the time window
      -certsissued
            certificates issued during the time window
      -certsrevoked
            certificates revoked during the time window

    ...

If `$GOPATH` is not in your `$PATH`, then you can run **hvclient** by fully
qualifying the path to the executable:

    jdoe@host:hvclient$ /home/jdoe/src/go/bin/hvclient -h
    Usage of hvclient:
      -certsexpiring
            certificates expiring during the time window
      -certsissued
            certificates issued during the time window
      -certsrevoked
            certificates revoked during the time window

    ...

or by copying the executable file into a folder which is in your `$PATH`:

    jdoe@host:hvclient$ echo $PATH
    /usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/home/jdoe/bin
    jdoe@host:hvclient$ cp /home/jdoe/src/go/bin/hvclient /home/jdoe/bin
    jdoe@host:hvclient$ hvclient -h
    Usage of hvclient:
      -certsexpiring
            certificates expiring during the time window
      -certsissued
            certificates issued during the time window
      -certsrevoked
            certificates revoked during the time window

    ...

A more permanent solution is to modify your `.profile` or `.bash_profile`
file to permanently add `$GOPATH/bin` to your `$PATH`, for example, before
the change:

    jdoe@host:~$ cat .bash_profile
    # if running bash
    if [ -n "$BASH_VERSION" ]; then
        if [ -f "$HOME/.bashrc" ]; then
            . "$HOME/.bashrc"
        fi
    fi
    jdoe@host:~$

and after making the change (make sure to change the path to match your `$GOPATH`):

    jdoe@host:~$ cat .bash_profile
    # if running bash
    if [ -n "$BASH_VERSION" ]; then
        if [ -f "$HOME/.bashrc" ]; then
            . "$HOME/.bashrc"
        fi
    fi

    if [ -d "$HOME/src/go/bin" ]; then
        PATH="$HOME/src/go/bin:$PATH"
    fi
    jdoe@host:~$


## Usage

Using the **hvclient** utility requires:

 1. An HCVA account;
 2. A configuration file; and
 3. A certificate/key pair for the TLS connection to the HVCA system.


### Configuration file

The configuration file is JSON-encoded and should match the following format:

    {
        "url": "https://emea.api.hvca.globalsign.com:8443/v2",
        "api_key": "value_of_api_key",
        "api_secret": "value_of_api_secret",
        "cert_file": "/path/to/mTLS/certificate.pem",
        "key_file": "/path/to/mTLS/private_key.pem",
        "key_passphrase": "passphrase",
        "timeout": 60
    }

The key_passphrase field may be omitted in the unlikely event the private key
file is not encrypted. The timeout field may be omitted, and a reasonable
default timeout will be applied.

The configuration file may be specified with the `-config` option. If this
option is not specified, **hvclient** will look for a configuration file with
the path `$HOME/.hvclient/hvclient.conf`.

### Options

Invoking **hvclient** with the `-h` option will show a list of available options
and flags.

### Requesting a certificate

Requesting a certificate requires three things:

1. Specifying the validity period;

2. Providing the public key and proof-of-possession of the private key; and

3. Specifying the requested values of the certificate fields.

*Note*: in the examples that follow, the `-generate` option will show the
JSON-encoded request that would be provided to HVCA, without actually making
the certificate request. This is useful for verifying the request that
HVClient will make before actually submitting it.

#### Specifying the validity period

If the validity period is not specified at all, the not-before time will
default to the current time, and the not-after time will default to the
maximum allowed by the validation policy.

The next simplest option is to specify a certificate duration with the
`-duration` option. The not-before time will default to the current time,
and the not-after time will be calculated as the current time plus the
specified duration. The duration may be specified in a variety of formats
such as `5weeks`, `30d`, `90days`, `24h`, and so on.

Finally, the `-notbefore` and `-notafter` options may be used to set the
not-before and not-after times explicitly. The times must be given in a
format matching `2018-10-31T08:45:12EST`.

#### Providing the public key

A public key must always be provided to request a certificate. An HVCA
account may also be set up to require that the requestor prove they are in
possession of the private key corresponding to that public key. This proof
may be in one of two forms:

1. Signing the public key with the private key; or

2. Provided a PKCS#10 certificate signing request (CSR) signed with the private
key. Note that when a PKCS#10 is provided, HVCA will only consider the public
key and the signature, and will ignore all the other fields. If any fields
in the CSR need to be included in the issued certificate, they must be
manually requested in the same way as any other field.

Three options are provided to provide the public key. In all cases, the value
of the option should be the path to a file containing the PEM-encoded key or
CSR:

1. `-publickey` - use this option for an HVCA account which does not require
proof-of-possession.

2. `-privatekey` - use this option for an HVCA account which requires
proof-of-possession by signing the public key with the private key. HVClient
will automatically extract the public key from the private key and compute
the signature. If the private key is encrypted, HVClient will prompt the user
for the decryption passphrase.

3. `-csr` - use this option for an HVCA account which requires
proof-of-possesion by providing a PKCS#10 CSR signed with the private key.
As a convenience, in the event the user has this kind of HVCA account but
doesn't have a PKCS#10 CSR, the `-gencsr` option can be combined with the
`-privatekey` option and HVClient will automatically generate a CSR and
sign it with that private key.

Some examples follow demonstrating the validity period and public key options:

    jdoe@host:~$ hvclient -generate -publickey="testdata/rsa_pub.key"
    {
        "validity": {
            "not_before": 1550560897,
            "not_after": 0
        },
        "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs1FninypAx/n4OHxpaPe\nMLJAfhlHa4c8wjkRumhPRUhlcKT7f4vlgRaNO/djOUZPV1kO1h8qtjRznfFZvgNb\nH1oGGbRqxwT0qnmCyhp5tv7rcoPsgBASVH7t1+5LAAU0GSGTEwTNDvIgh1sV3uw7\nvunqZjgFKnG3ONAVyNYG/Mr9qLn72ze3DnZRyrvkjl12ddyMCRlOszQMIpvZoAPF\nANyE5u9mMmMUQCQJfv51b7/VZqJSqV+vCVkZTbtA2anG3zJyoaByC6+EMrXN8u1l\neC3QHuKUU18B/4jFCaa12MBetepa3v4DSSU+c53O74mXzrFbc8ICxDgq1ID0Ev2z\nTwIDAQAB\n-----END PUBLIC KEY-----"
    }
    jdoe@host:~$ hvclient -generate -duration="30d" -privatekey="testdata/rsa_priv.key"
    {
        "validity": {
            "not_before": 1550560920,
            "not_after": 1553152920
        },
        "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs1FninypAx/n4OHxpaPe\nMLJAfhlHa4c8wjkRumhPRUhlcKT7f4vlgRaNO/djOUZPV1kO1h8qtjRznfFZvgNb\nH1oGGbRqxwT0qnmCyhp5tv7rcoPsgBASVH7t1+5LAAU0GSGTEwTNDvIgh1sV3uw7\nvunqZjgFKnG3ONAVyNYG/Mr9qLn72ze3DnZRyrvkjl12ddyMCRlOszQMIpvZoAPF\nANyE5u9mMmMUQCQJfv51b7/VZqJSqV+vCVkZTbtA2anG3zJyoaByC6+EMrXN8u1l\neC3QHuKUU18B/4jFCaa12MBetepa3v4DSSU+c53O74mXzrFbc8ICxDgq1ID0Ev2z\nTwIDAQAB\n-----END PUBLIC KEY-----",
        "public_key_signature": "Wm4269dSz4VYZvAzeIO8pB0a9UhZkonvrgHcLisLoRMceAqgdPb1HI/midwqZTXQBdiCgi2Eo3Dww3efSvGT1rgx9YUSaOmBJwduAsEwywd8MuirSZqoP1EG20hfLDj8aRFbVTobWR+YZ0E0Ws+LGqi1DQDZqenOD4fJIKW3dcqwWBRRbEVFduZK6sNkHf6bovLl+3zAov7JVjMgyMIPapPaQ/yFO3eSt7e5gGdknTp/tPm8g7OprAqOYXN3IKTV0v5N4yuDE6soRYfc40X0GUiLV9PPuSLIUC1C5NgPeK6KoyRne65rS9ewheDhH8jYzhqT8dXOGdTovVOAqDsMFA=="
    }
    jdoe@host:~$ hvclient -generate -notbefore="2018-02-18T06:00:00EST" -notafter="2018-05-18T06:00:00EST" -csr="testdata/request.p10"
    {
        "validity": {
            "not_before": 1518951600,
            "not_after": 1526641200
        },
        "public_key": "-----BEGIN CERTIFICATE REQUEST-----\nMIICmDCCAYACAQAwEzERMA8GA1UEAxMISmFuZSBEb2UwggEiMA0GCSqGSIb3DQEB\nAQUAA4IBDwAwggEKAoIBAQCzUWeKfKkDH+fg4fGlo94wskB+GUdrhzzCORG6aE9F\nSGVwpPt/i+WBFo0792M5Rk9XWQ7WHyq2NHOd8Vm+A1sfWgYZtGrHBPSqeYLKGnm2\n/utyg+yAEBJUfu3X7ksABTQZIZMTBM0O8iCHWxXe7Du+6epmOAUqcbc40BXI1gb8\nyv2oufvbN7cOdlHKu+SOXXZ13IwJGU6zNAwim9mgA8UA3ITm72YyYxRAJAl+/nVv\nv9VmolKpX68JWRlNu0DZqcbfMnKhoHILr4Qytc3y7WV4LdAe4pRTXwH/iMUJprXY\nwF616lre/gNJJT5znc7viZfOsVtzwgLEOCrUgPQS/bNPAgMBAAGgQDA+BgkqhkiG\n9w0BCQ4xMTAvMAsGA1UdDwQEAwIDqDAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAQYI\nKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggEBABrJuAilwmKxyQBWekAI7jGBSxo6\ng6nimuzSCsVJ9w/3gltNuILaZNBwFYrCwUnr24wfb69PuHzjvhNiO+QOFcAJH0Kw\nh8kY7eK43krgzNT49iSN3mJilIN2CRhfgLWNhIQz1jrm/99Flyg8oU4JC3gKq9rt\narljy85LRwO/5rzkDpGKlwR2i0J9VPMV6dpbAsMBnncJlBodEhF0xvQ6VqRxpfdX\np1WjKGyqTUuHiMV99eB8udb/SNQsspiAG0Mflx5DZlXqCEgbmJHOe3PuBu7N0N9U\n98yIGOjfDmPjo53O178/Ij7x1HzpPBORZYOAFRKKYcoLNbNCPmYcXS30+QI=\n-----END CERTIFICATE REQUEST-----"
    }
    jdoe@host:~$ hvclient -generate -notbefore="2018-02-18T06:00:00EST" -duration="90d" -privatekey="testdata/ec_priv.key" -gencsr
    {
        "validity": {
            "not_before": 1518951600,
            "not_after": 1526727600
        },
        "public_key": "-----BEGIN CERTIFICATE REQUEST-----\nMIG5MGICAQAwADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPUjSCcvNwZjgYsM\nq1a6DhOogRZp0MmkmC7wSwvI934o60IYP4e5eiBh2GSXkcZL0/3bli/2R4XPzfzf\n2qFExUygADAKBggqhkjOPQQDAgNHADBEAiBLiTsd7q5+VyE1/+IocMS7R6bvVWfv\nt2X74lvIzBS+GgIgJgnXS/9/Y6wJgdzar+BE8W1fX0Ir2XJOgKmg3qmjP9s=\n-----END CERTIFICATE REQUEST-----"
    }
    jdoe@host:~$

#### Specifying the certificate field values.

A large number of options are available to specify the requested certificate
field values. 

The following options may be used to specify the values for the subject
distinguished name:

    -commonname           subject common name
    -organization         subject organization
    -organizationalunit   subject organizational units (can be a comma-separate list for multiple values)
    -streetaddress        subject street address
    -locality             subject locality, town or city
    -state                subject state or province
    -country              subject country
    -email                subject email address (deprecated, use subject alternative names instead)
    -joilocality          jurisdiction locality
    -joistate             jurisdiction state or province
    -joicountry           jurisdiction country
    -businesscategory     business category
    -extra atttributes    extra attributes, in the form '2.5.4.4=surname,2.5.4.5=serial_number'

The following options may be used to specify the values for the subject
alternative names:

    -dnsnames             comma-separated list of domains
    -emails               comma-separated list of email addresses
    -ips                  comma-separated list of IP addresses
    -uris                 comma-separated list of URIs

The following option may be used to specify any requested extended key usages:

    -ekus                 comma-separated list of OIDs, e.g. '1.3.6.1.5.5.7.3.1, 1.3.6.1.5.5.7.3.2'

Some examples follow demonstrating the use of these options:

    jdoe@host:~$ hvclient -generate -publickey="testdata/rsa_pub.key" -commonname="John Doe"
    {
        "validity": {
            "not_before": 1550562050,
            "not_after": 0
        },
        "subject_dn": {
            "common_name": "John Doe"
        },
        "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs1FninypAx/n4OHxpaPe\nMLJAfhlHa4c8wjkRumhPRUhlcKT7f4vlgRaNO/djOUZPV1kO1h8qtjRznfFZvgNb\nH1oGGbRqxwT0qnmCyhp5tv7rcoPsgBASVH7t1+5LAAU0GSGTEwTNDvIgh1sV3uw7\nvunqZjgFKnG3ONAVyNYG/Mr9qLn72ze3DnZRyrvkjl12ddyMCRlOszQMIpvZoAPF\nANyE5u9mMmMUQCQJfv51b7/VZqJSqV+vCVkZTbtA2anG3zJyoaByC6+EMrXN8u1l\neC3QHuKUU18B/4jFCaa12MBetepa3v4DSSU+c53O74mXzrFbc8ICxDgq1ID0Ev2z\nTwIDAQAB\n-----END PUBLIC KEY-----"
    }
    jdoe@host:~$ hvclient -generate -publickey="testdata/rsa_pub.key" -commonname="John Doe" -organizationalunit="Sales,Marketing" -organization="ACME Inc" -extraattributes="2.5.4.5=Doe" -emails="jdoe@acme.com" -ekus="1.3.6.1.5.5.7.3.1, 1.3.6.1.5.5.7.3.2"
    {
        "validity": {
            "not_before": 1550562051,
            "not_after": 0
        },
        "subject_dn": {
            "organization": "ACME Inc",
            "organizational_unit": [
                "Sales",
                "Marketing"
            ],
            "common_name": "John Doe",
            "extra_attributes": [
                {
                    "type": "2.5.4.5",
                    "value": "Doe"
                }
            ]
        },
        "san": {
            "emails": [
                "jdoe@acme.com"
            ]
        },
        "extended_key_usages": [
            "1.3.6.1.5.5.7.3.1",
            "1.3.6.1.5.5.7.3.2"
        ],
        "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs1FninypAx/n4OHxpaPe\nMLJAfhlHa4c8wjkRumhPRUhlcKT7f4vlgRaNO/djOUZPV1kO1h8qtjRznfFZvgNb\nH1oGGbRqxwT0qnmCyhp5tv7rcoPsgBASVH7t1+5LAAU0GSGTEwTNDvIgh1sV3uw7\nvunqZjgFKnG3ONAVyNYG/Mr9qLn72ze3DnZRyrvkjl12ddyMCRlOszQMIpvZoAPF\nANyE5u9mMmMUQCQJfv51b7/VZqJSqV+vCVkZTbtA2anG3zJyoaByC6+EMrXN8u1l\neC3QHuKUU18B/4jFCaa12MBetepa3v4DSSU+c53O74mXzrFbc8ICxDgq1ID0Ev2z\nTwIDAQAB\n-----END PUBLIC KEY-----"
    }
    jdoe@host:~$ 

When requesting multiple certificates which share static or commonly-used field
values, HVClient can initialize a request from a template file specified with
the `-template` option. Any single value fields can be overrided at the command
line, and any list value fields (such as the subject alternative names values)
may be appended to from the command line. 

For example:

    jdoe@host:~$ cat base.tmpl
    {
        "subject_dn": {
            "organizational_unit": [
                "Administration"
            ],
            "organization": "ACME Marble Company",
            "country": "US"
        },
        "extended_key_usages": [
            "1.3.6.1.5.5.7.3.1",
            "1.3.6.1.5.5.7.3.2"
        ],
        "ms_extension_template": {
            "id": "1.2.3.4.123.4.5.1",
            "major_version": 1,
            "minor_version": 2
        }
    }
    jdoe@host:~$ hvclient -generate -template="base.tmpl" -publickey="testdata/ec_pub.key" -commonname="Jane Doe" -organizationalunit="Operations,Logistics"
    {
        "validity": {
            "not_before": 1550562671,
            "not_after": 0
        },
        "subject_dn": {
            "country": "US",
            "organization": "ACME Marble Company",
            "organizational_unit": [
                "Administration",
                "Operations",
                "Logistics"
            ],
            "common_name": "Jane Doe"
        },
        "extended_key_usages": [
            "1.3.6.1.5.5.7.3.1",
            "1.3.6.1.5.5.7.3.2"
        ],
        "ms_extension_template": {
            "id": "1.2.3.4.123.4.5.1",
            "major_version": 1,
            "minor_version": 2
        },
        "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9SNIJy83BmOBiwyrVroOE6iBFmnQ\nyaSYLvBLC8j3fijrQhg/h7l6IGHYZJeRxkvT/duWL/ZHhc/N/N/aoUTFTA==\n-----END PUBLIC KEY-----"
    }
    jdoe@host:~$

#### Generating a PKCS#10 certificate signing request

As a convenience, the `generate` option can be replaced by `-csrout` and
HVClient will create and output a PKCS#10 CSR instead of requesting a
certificate.

For example:

    jdoe@host:~$ hvclient -csrout -template="base.tmpl" -privatekey="testdata/ec_priv.key" -commonname="Jane Doe" -organizationalunit="Operations,Logistics" -dnsnames="marketing.acme.com" > request.p10
    jdoe@host:~$ openssl req -in request.p10 -text -noout
    Certificate Request:
        Data:
            Version: 0 (0x0)
            Subject: C=US, O=ACME Marble Company, OU=Administration, OU=Operations, OU=Logistics, CN=Jane Doe
            Subject Public Key Info:
                Public Key Algorithm: id-ecPublicKey
                    Public-Key: (256 bit)
                    pub:
                        04:f5:23:48:27:2f:37:06:63:81:8b:0c:ab:56:ba:
                        0e:13:a8:81:16:69:d0:c9:a4:98:2e:f0:4b:0b:c8:
                        f7:7e:28:eb:42:18:3f:87:b9:7a:20:61:d8:64:97:
                        91:c6:4b:d3:fd:db:96:2f:f6:47:85:cf:cd:fc:df:
                        da:a1:44:c5:4c
                    ASN1 OID: prime256v1
                    NIST CURVE: P-256
            Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name:
                    DNS:marketing.acme.com
                X509v3 Extended Key Usage:
                    TLS Web Server Authentication, TLS Web Client Authentication
        Signature Algorithm: ecdsa-with-SHA256
             30:44:02:20:2f:cd:ed:96:2a:3f:4c:ab:8f:9b:c2:e0:cf:a9:
             dd:cb:06:25:34:22:3f:79:e7:60:3f:ff:d4:69:9f:6e:66:d2:
             02:20:12:b5:d1:0d:5c:5e:5f:05:b7:07:37:3a:83:1e:83:d6:
             2f:9f:c9:79:d9:92:f3:1b:84:eb:bd:f9:ef:17:ba:f8
    jdoe@host:~$

### Basic statistics

The following options will output basic statistics about the calling account:

 * `-countissued` - count of total number of certificates issued by the account
 * `-countrevoked` - count of the total number of certificates issued by the account
 * `-quota` - remaining quota of certificate issuances for the account
 * `-trustchain` - the chain of trust for the certificates issued by the account
 * `-policy` - the validation policy for certificate issuance requests

Example usage:

    user@host:hvclient$ hvclient -countissued
    118
    user@host:hvclient$ hvclient -countrevoked
    3
    user@host:hvclient$ hvclient -quota
    999881
    user@host:hvclient$ hvclient -trustchain
    -----BEGIN CERTIFICATE-----
    MIIDbjCCAlagAwIBAgIOSETcwm+2g5xjwYbw8ikwDQYJKoZIhvcNAQELBQAwUjEL
    MAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKDAmBgNVBAMT
    H0dsb2JhbFNpZ24gTm9uLVB1YmxpYyBIVkNBIERlbW8wHhcNMTYwNzIwMDAwMDAw
    WhcNMjYwNzIwMDAwMDAwWjBSMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
    U2lnbiBudi1zYTEoMCYGA1UEAxMfR2xvYmFsU2lnbiBOb24tUHVibGljIEhWQ0Eg
    RGVtbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALZr0Una3n3CTWMf
    +TGoc3sFXqWIpAasR2ULxVuziCQVs7Z2/ha6iNhQ2JITZzTu5ZZHwrgvxTwdLSq7
    Y9H22u1sahJYMElQOsoEMERwGKGU92HpqxrinYi54mZ0xU1vYVyMAPfOvOh9NUgo
    KXCuza27wIfl00A7HO8nq0hoYxmezrVIUyObLuQir43mwruov31nOhFeYqxNWPkQ
    VDGOBqRGp6KkEMlKsV9/Tyw0JyRko1cDukS6Oacv1NSU4rz6+aYqvCQSZEy5IbUd
    KS46aQ1FO9c4jVhJ3uTzJ/nJ5W4B9RP//JpLt2ey9XvfvuJW8s9qjJtY18frgCoD
    yilhHk0CAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8w
    HQYDVR0OBBYEFGdLB+kJ8fF7Msy9hRxOJw3OocxsMA0GCSqGSIb3DQEBCwUAA4IB
    AQBQIVeyhjtZ+T30LY8AlVe0jya9yBuCSqXld9Lesm1RiE2MIjW1cDueKlxa6DFT
    7Ysm+s0Q171r5JB/ZgLG2TyjCBEocxSLdYrBy+V3Gb9sN2KToyeE01nTrK85E+Tp
    JXVAlgfuYsntV5GQ/cut+Wpl6QuJHfXWRcXQo0/nNG15A79Z84LTcM0f5qVkvDTC
    OXiCVR4HYFF5G39qaKaBCVuWnBCOdNKF7ESQVxc1UDibTFLFxHHKd8hrHe7mdSip
    jkU8e4uzGpVAnJGLYncRQtowXHPc14prEcYvzxvXphgF1RYdp9Tu0wAha+Tjt0VL
    eFSle46vwuyv8BzkS+rQJ8Kb
    -----END CERTIFICATE-----
    user@host:hvclient$ hvclient -policy
    {
       "validity": {
          "not_before_negative_skew": 200,
          "not_before_positive_skew": 200,
          "secondsmax": 7776000,
          "secondsmin": 60
       },
       "subject_dn": {
          "business_category": {
             "format": "",
             "presence": "FORBIDDEN"
          },
          "common_name": {
             "format": "^[a-zA-Z0-9\\\\s]+$",
             "presence": "REQUIRED"
          },
          "country": {
             "format": "",
             "presence": "FORBIDDEN"
          },
          "email": {
             "format": "",
             "presence": "FORBIDDEN"
          },
          "jurisdiction_of_incorporation_country_name": {
             "format": "",
             "presence": "FORBIDDEN"
          },
          "jurisdiction_of_incorporation_locality_name": {
             "format": "",
             "presence": "FORBIDDEN"
          },
          "jurisdiction_of_incorporation_state_or_province_name": {
             "format": "",
             "presence": "FORBIDDEN"
          },
          "locality": {
             "format": "",
             "presence": "FORBIDDEN"
          },
          "organization": {
             "format": "Acme Retail Inc",
             "presence": "STATIC"
          },
          "organizational_unit": {
             "list": [
                "^.*$"
             ],
             "maxcount": 3,
             "mincount": 0,
             "static": false
          },
          "state": {
             "format": "",
             "presence": "FORBIDDEN"
          },
          "street_address": {
             "format": "",
             "presence": "FORBIDDEN"
          }
       },
       "san": {
          "critical": false,
          "dns_names": {
             "list": [
                "."
             ],
             "maxcount": 5,
             "mincount": 0,
             "static": false
          },
          "emails": {
             "list": [],
             "maxcount": 0,
             "mincount": 0,
             "static": false
          },
          "ip_addresses": {
             "list": [],
             "maxcount": 0,
             "mincount": 0,
             "static": false
          },
          "other_names": null,
          "uris": {
             "list": [],
             "maxcount": 0,
             "mincount": 0,
             "static": false
          }
       },
       "extended_key_usages": {
          "critical": false,
          "ekus": {
             "list": [
                "1.3.6.1.5.5.7.3.2"
             ],
             "maxcount": 1,
             "mincount": 1,
             "static": true
          }
       },
       "custom_extensions": {},
       "public_key": {
          "allowed_lengths": [
             2048
          ],
          "key_type": "RSA"
       },
       "public_key_signature": "FORBIDDEN"
    }
    user@host:hvclient$

#### List-producing APIs - time window

A number of HVCA APIs return a list of items for a given time period. Examples include:

 * `-certsissued` - a list of certificates issued over a given time period
 * `-certsrevoked` - a list of certificates revoked over a given time period
 * `-certsexpiring` - a list of certificates expiring during a given time period

The following options are provided for specifying the time period:

 * `-from` - takes a time string in the layout `2006-01-02T15:04:05MST`. If this option
 is not specified, a default time of 30 days prior to the current moment will be used.
 * `-to` - takes a time string in the layout `2006-01-02T15:04:05MST`. If this option is
 not specified, a default of the current moment will be used.
 * `-since` - takes a duration in a variety of layouts including `-60s`, `120seconds`,
 `20m`, `3hrs`, `24h`, `5d` and `30days`. `-since` always computes a time window from
 the current time going back by the specified duration.
 
The `-to` option can always be omitted. The `-from` option cannot be omitted it the `-to`
option is specified. `-since` cannot be combined with either `-from` or `-to`.

Example usage:

    user@host:hvclient$ hvclient -certsissued -from="2018-10-05T00:00:00EST" -to="2018-10-05T23:59:59EST"
    01CFABDF1EBA6325930BF8B6FFD89F12,2018-10-05 10:10:59 -0400 EDT,2019-01-03 07:30:59 -0500 EST
    01F61750041A52E5561F0DC342A4BF3D,2018-10-05 10:15:44 -0400 EDT,2019-01-03 07:35:44 -0500 EST
    01BE04ABA4D398ABA21D3C6E56274D18,2018-10-05 10:18:33 -0400 EDT,2019-01-03 07:38:33 -0500 EST
    0120706646DB29EDC8F168F76ACE65C1,2018-10-05 10:21:27 -0400 EDT,2019-01-03 07:41:27 -0500 EST
    user@host:hvclient$ hvclient -certsrevoked -from="2018-10-05T00:00:00EST" -to="2018-10-05T23:59:59EST"
    01CFABDF1EBA6325930BF8B6FFD89F12,2018-10-05 10:10:59 -0400 EDT,2019-01-03 07:30:59 -0500 EST
    user@host:hvclient$ hvclient -certsexpiring -since="30m"
    01C070FF85F87F26647EEFCB0B24FEF8,2018-10-08 15:12:54 -0400 EDT,2018-10-09 15:12:54 -0400 EDT
    01D7C1A470F715D1EB8CC96E6EFEE6A8,2018-10-08 15:13:54 -0400 EDT,2018-10-09 15:13:54 -0400 EDT
    user@host:hvclient$ hvclient -certsexpiring -from="2018-10-09T15:06:00EDT"
    01C070FF85F87F26647EEFCB0B24FEF8,2018-10-08 15:12:54 -0400 EDT,2018-10-09 15:12:54 -0400 EDT
    01D7C1A470F715D1EB8CC96E6EFEE6A8,2018-10-08 15:13:54 -0400 EDT,2018-10-09 15:13:54 -0400 EDT
    user@host:hvclient$

The fields shown above are the certificate ID, the not-before time, and the not-after time. 

#### List-producing APIs - pages

A number of HVCA APIs return a list of items in a paged format. This includes the three APIs
in the preceding section, as well as:

 * `-claims` - a list of domain claims. If the `-pending` option is also specified, only
 pending claims are shown in the list. If the `-pending` option is not specified, only
 verified claims are shown in the list.

The following options are provided for dealing with the pages:

 * `-page` - the page number, defaulting to 1.
 * `-pagesize` - the number of items to show per page, defaulting to 100.
 * `-totalcount` - show the total count of items in the population. This may be used to
 calculate the number of pages of a given size that would be needed to view all the data.
 Note that when then `-totalcount` option is specified, the actual output of the items is
 suppressed, even if the `-page` or `-pagesize` options are specified.

Example usage:

    user@host:hvclient$ hvclient -certsissued -totalcount -from="2018-10-05T00:00:00EST" -to="2018-10-05T23:59:59EST"
    4
    user@host:hvclient$ hvclient -certsissued -page=1 -pagesize=2 -from="2018-10-05T00:00:00EST" -to="2018-10-05T23:59:59EST"
    01CFABDF1EBA6325930BF8B6FFD89F12,2018-10-05 10:10:59 -0400 EDT,2019-01-03 07:30:59 -0500 EST
    01F61750041A52E5561F0DC342A4BF3D,2018-10-05 10:15:44 -0400 EDT,2019-01-03 07:35:44 -0500 EST
    user@host:hvclient$ hvclient -certsissued -page=2 -pagesize=2 -from="2018-10-05T00:00:00EST" -to="2018-10-05T23:59:59EST"
    01BE04ABA4D398ABA21D3C6E56274D18,2018-10-05 10:18:33 -0400 EDT,2019-01-03 07:38:33 -0500 EST
    0120706646DB29EDC8F168F76ACE65C1,2018-10-05 10:21:27 -0400 EDT,2019-01-03 07:41:27 -0500 EST
    user@host:hvclient$ hvclient -certsissued -page=1 -pagesize=4 -from="2018-10-05T00:00:00EST" -to="2018-10-05T23:59:59EST"
    01CFABDF1EBA6325930BF8B6FFD89F12,2018-10-05 10:10:59 -0400 EDT,2019-01-03 07:30:59 -0500 EST
    01F61750041A52E5561F0DC342A4BF3D,2018-10-05 10:15:44 -0400 EDT,2019-01-03 07:35:44 -0500 EST
    01BE04ABA4D398ABA21D3C6E56274D18,2018-10-05 10:18:33 -0400 EDT,2019-01-03 07:38:33 -0500 EST
    0120706646DB29EDC8F168F76ACE65C1,2018-10-05 10:21:27 -0400 EDT,2019-01-03 07:41:27 -0500 EST
    user@host:hvclient$ hvclient -claims -pending -totalcount
    5
    user@host:hvclient$ hvclient -claims -pending -page=1 -pagesize=3
    0175759C429145957E87F7F0797A0967,PENDING,nothing.here.,2018-10-08 21:19:11 -0400 EDT,2018-11-07 20:19:11 -0500 EST
    01822EB556A858D84C42E9722AF7BEC5,PENDING,fake.domain.net.,2018-10-08 21:19:05 -0400 EDT,2018-11-07 20:19:05 -0500 EST
    01DC4FFB8B2168753B721CA5567A7B51,PENDING,not.real.org.,2018-10-08 21:18:52 -0400 EDT,2018-11-07 20:18:52 -0500 EST
    user@host:hvclient$ hvclient -claims -pending -page=2 -pagesize=3
    01E7872A04C0F3C8C83835B14DCFEC75,PENDING,banana.fruit.gov.,2018-10-08 20:13:32 -0400 EDT,2018-11-07 19:13:32 -0500 EST
    016B3BA9F4A57A2D4785D9EC5FD8EA89,PENDING,example.com.,2018-10-08 19:28:31 -0400 EDT,2018-11-07 18:28:31 -0500 EST
    user@host:hvclient$ hvclient -claims -pending -page=1
    0175759C429145957E87F7F0797A0967,PENDING,nothing.here.,2018-10-08 21:19:11 -0400 EDT,2018-11-07 20:19:11 -0500 EST
    01822EB556A858D84C42E9722AF7BEC5,PENDING,fake.domain.net.,2018-10-08 21:19:05 -0400 EDT,2018-11-07 20:19:05 -0500 EST
    01DC4FFB8B2168753B721CA5567A7B51,PENDING,not.real.org.,2018-10-08 21:18:52 -0400 EDT,2018-11-07 20:18:52 -0500 EST
    01E7872A04C0F3C8C83835B14DCFEC75,PENDING,banana.fruit.gov.,2018-10-08 20:13:32 -0400 EDT,2018-11-07 19:13:32 -0500 EST
    016B3BA9F4A57A2D4785D9EC5FD8EA89,PENDING,example.com.,2018-10-08 19:28:31 -0400 EDT,2018-11-07 18:28:31 -0500 EST
    user@host:hvclient$ hvclient -claims -totalcount
    0
    user@host:hvclient$ hvclient -claims
    user@host:hvclient$

The account used for the above example has no verified domain claims. The pending claims
list fields are claim ID, status, domain, created-at time, and assert-by time.

#### Information about certificates and claims

The following options may be used to show information about specific certificates or claims:

 * `-retrieve` - the certificate with the specified ID
 * `-status` - the status of the certificate with the specified ID
 * `-updated` - the updated-at time of the certificate with the specified ID
 * `-info` - a convenience option to show detailed of a certificate in the specified file.
 * `-claimretrieve` - details of the domain claim with the specified ID

Example usage:

    user@host:hvclient$ hvclient -retrieve="01F61750041A52E5561F0DC342A4BF3D"
    -----BEGIN CERTIFICATE-----
    MIIEajCCA1KgAwIBAgIQAfYXUAQaUuVWHw3DQqS/PTANBgkqhkiG9w0BAQsFADBS
    MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEoMCYGA1UE
    AxMfR2xvYmFsU2lnbiBOb24tUHVibGljIEhWQ0EgRGVtbzAeFw0xODEwMDUxNDE1
    NDRaFw0xOTAxMDMxMjM1NDRaMDkxHzAdBgNVBAoMFkdsb2JhbFNpZ24gRW5naW5l
    ZXJpbmcxFjAUBgNVBAMMDU1pY2hhZWxLbmlnaHQwggEiMA0GCSqGSIb3DQEBAQUA
    A4IBDwAwggEKAoIBAQCpfQZsiz+W0GoZMrq4uz3BjOj8hGu0mrvIMCf7TNPsGDpD
    3LTKsZojBxaz/kN7/I/Zs+0npeSYsxuUHviqgpSPGTiAhPNBl/cUtnuEGbaR7KRv
    euPSFxvdoilBqayfQu2ckbbbsanXsBwmR5IARZMeTCNqSK1JUG1jNxocLS0VRw9/
    WXKdlKxYq6A+T7Gihl+j9PudGRZMSCUOHmosYXemdabqvo2oFuXx++Nuz6jGDfoP
    zih2zYfK8nMlDUJb5Skq5loVqyOn2Qcxbl/+hDITAeT2/+hlNxRPb/il/1dk1kJJ
    YfzOfNbZtaUKvvtaLXoV9H1Kz966wkFvfU2GakynAgMBAAGjggFTMIIBTzAdBgNV
    HQ4EFgQUAJdLQy0nHG47Ogr/LcZ+1p/iGI8wCQYDVR0TBAIwADAfBgNVHSMEGDAW
    gBRnSwfpCfHxezLMvYUcTicNzqHMbDAOBgNVHQ8BAf8EBAMCA6gwgZYGCCsGAQUF
    BwEBBIGJMIGGMDwGCCsGAQUFBzABhjBodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNv
    bS9jYS9nc25waHZjYWRlbW9zaGEyZzMwRgYIKwYBBQUHMAKGOmh0dHA6Ly9zZWN1
    cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzbnBodmNhZGVtb3NoYTJnMy5jcnQw
    RAYDVR0fBD0wOzA5oDegNYYzaHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9jYS9n
    c25waHZjYWRlbW9zaGEyZzMuY3JsMBMGA1UdJQQMMAoGCCsGAQUFBwMCMA0GCSqG
    SIb3DQEBCwUAA4IBAQAalJDXsKyGgOh/si0pM8z/5M3QtFBUmBKZwXrAz7ySreEC
    +Ns5WlsukZsZxiAm+wspA6moYY6oqHeGluIYwweCXpvHBHDmeB682kUf54WhyYGE
    lGXN095Bp/ZL+9Z7RNlKao0N08+3Gyv7d4P6+Xa8PdbAbRMuiBbkqcL1kfgsrpZF
    XdJzAKJTHBzze9H3JRNX7ISChWJpdyKiw9/Boi3PBWqc3r298WyWWM1S7aB21pE7
    DPVdnou5xHKtbqeuDYPwN7jI80hmQaDsQbMHlqqQLYGCbHQ51DSMpyBqBp8WlyFn
    QgcNybbp5BzIRlFB7QI+3XC8yQlCHB+vGqpvV8ID
    -----END CERTIFICATE-----
    user@host:hvclient$ hvclient -status="01F61750041A52E5561F0DC342A4BF3D"
    ISSUED
    user@host:hvclient$ hvclient -status="01CFABDF1EBA6325930BF8B6FFD89F12"
    REVOKED
    user@host:hvclient$ hvclient -updated="01CFABDF1EBA6325930BF8B6FFD89F12"
    2018-10-05 10:43:42 -0400 EDT
    user@host:hvclient$ hvclient -info="cert.pem"
    Serial Number        : 17FFD67D2363AB776A579D7034BB621
    Not Before           : 2018-10-07 19:43:12 +0000 UTC
    Not After            : 2019-01-05 19:43:12 +0000 UTC
    Version              : 3
    Subject              : CN=JackFrost,O=Acme Retail Engineering
    Issuer               : CN=GlobalSign Non-Public HVCA Demo,O=GlobalSign nv-sa,C=BE
    Public Key Algorithm : RSA
    user@host:hvclient$ hvclient -claimretrieve="016B3BA9F4A57A2D4785D9EC5FD8EA89"
    016B3BA9F4A57A2D4785D9EC5FD8EA89,PENDING,example.com.,2018-10-08 19:28:31 -0400 EDT,2018-11-07 18:28:31 -0500 EST
    user@host:hvclient$ 

#### Revoking and deleting

A certificate may be revoked with the `-revoke` option, and a domain claim may be
deleted with the `-claimdelete` option.

Example usage:

    user@host:hvclient$ hvclient -revoke="01F61750041A52E5561F0DC342A4BF3D"
    user@host:hvclient$ hvclient -claimdelete="016B3BA9F4A57A2D4785D9EC5FD8EA89"
    user@host:hvclient$

#### Submitting a new domain claim

A new claim for a domain may be submitted with the `-claimsubmit` option.

Example usage:

    user@host:hvclient$ hvclient -claimsubmit="nothing.to.see.here.com"
    01b5c8bded51b4ab05d51cd8b85ba88e,2018-11-07 20:39:41 -0500 EST,01A4B882B7A8FBFBF01AECE65F84C20C
    user@host:hvclient$ hvclient -claimretrieve="01A4B882B7A8FBFBF01AECE65F84C20C"
    01A4B882B7A8FBFBF01AECE65F84C20C,PENDING,nothing.to.see.here.com.,2018-10-08 21:39:41 -0400 EDT,2018-11-07 20:39:41 -0500 EST
    user@host:hvclient$ 

The fields shown by the `-claimsubmit` option are the claim token, the assert-by
date, and the claim ID.

#### Reasserting an existing domain claim

An existing domain claim may be reasserted with the `-claimreassert` option.

Example usage:

    user@host:hvclient$ hvclient -claimreassert="01A4B882B7A8FBFBF01AECE65F84C20C"
    01997ae1a5536a4bb005a428c5085daf,2018-11-08 14:37:46 -0500 EST
    user@host:hvclient$ 

#### Requesting assertion of domain control using DNS

Assertion of domain control using DNS can be requested with the `-claimdns` option, once
the token has been appropriately placed.

Example usage:

    user@host:hvclient$ hvclient -claimdns="01A4B882B7A8FBFBF01AECE65F84C20C"
    CREATED
    user@host:hvclient$ 

The response will be `CREATED` until the domain control has been verified, at which point
the response will be `VERIFIED`.

#### Requesting assertion of domain control using HTTP

Assertion of domain control using HTTP can be requested with the `-claimhttp` option, once
the token has been appropriately placed.

Example usage:

    user@host:hvclient$ hvclient -claimhttp="01A4B882B7A8FBFBF01AECE65F84C20C" -authdomain=test.com
    CREATED
    user@host:hvclient$ 

The response will be `CREATED` until the domain control has been verified, at which point
the response will be `VERIFIED`.
