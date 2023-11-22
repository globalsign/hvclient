/*
Copyright (c) 2019-2021 GMO GlobalSign Pte. Ltd.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import "fmt"

var helpDoc = `Usage: hvclient [options]

HVClient is a command-line interface to the GlobalSign Atlas Certificate
Management API (HVCA). 

Access to HVCA requires an account. At the time of account setup, GlobalSign
will provide a mutual TLS certificate, an API key, and an API secret which can
be provided to HVClient via a configuration file.

General options:

  -config=<file>        File containing configuration options and HVCA account
                        credentials. Defaults to $HOME/.hvclient/hvclient.conf.

Certificate request options:

  Key options:

    One (and only one) of -publickey, -privatekey or -csr must be specified to
    request a new certificate.

    -publickey=<file>   Public key to use for HVCA accounts which do not
                        require proof-of-possession of a private key.

    -privatekey=<file>  Private key to use for HVCA accounts which require
                        proof-of-possession by signing the public key.

        -gencsr         Generate a PKCS#10 certificate signing request (CSR)
                        for HVCA accounts which require proof-of-possession
                        with a signed PKCS#10 CSR. Useful when a user has an
                        HVCA account which requires this proof-of-possession,
                        but has no convenient way to generate their own CSR.

        -csrout         Output a PEM-encoded signed PKCS#10 CSR instead of
                        requesting a certificate from HVCA.

    -csr=<file>         PKCS#10 CSR to use for HVCA accounts which require
                        proof-of-possession with a signed PKCS#10 CSR.

    -generate           Use with -publickey, -privatekey or -csr to output
                        the JSON-encoded certificate request without actually
                        submitting it to HVCA. Useful for examining and
                        verifying the contents of a request before submitting
                        it.

  Validity period options:

    If all of these options are omitted, the request will default to a
    not-before time of the current time, and a not-after time of the maximum
    allowed by the account validation policy. Providing only -duration will
    default to a not-before time of the current time, and a not-after time
    of the current time plus the specified duration.

    -notbefore=<time>   The time before which the certificate is not valid. The
                        time format is 2016-01-02T15:04:05UTC. Defaults to the
                        current time.
    -notafter=<time>    The time after which the certificate is not valid. The
                        time format is 2016-01-02T15:04:05UTC. Defaults to the
                        maximum allowed by the account validation policy.
    -duration=<value>   An alternative to -notafter. The not-after time will be
                        calculated at the not-before time plus the specified
                        duration value, which should be in a flexible format
                        such as 10d, 30days, 24hrs, 8wk, 12w.

  Certificate attribute value options:

    At least one of these options should normally be selected.

    -commonname=<string>          Subject distinguished name (DN) common name
    -serialnumber=<string>        Subject DN serial number
    -organization=<string>        Subject DN organization
    -organizationalunit=<string>  Comma-separated list of subject DN
                                  organizational units
    -streetaddress=<string>       Subject DN street address
    -locality=<string>            Subject DN locality
    -state=<string>               Subject DN state or province
    -country=<string>             Subject DN country
    -email=<string>               Subject DN email address (deprecated, use
                                  subject alternative names instead)
    -businesscategory=<string>    Subject DN business category
    -joilocality=<string>         Subject DN jurisdiction locality
    -joistate=<string>            Subject DN jurisdiction state or province
    -joicountry=<string>          Subject DN jurisdiction country
    -extraattributes=<string>     Comma-separated list of subject DN extra
                                  attributes in format OID=value, for example
                                  "2.5.4.4=surname,2.5.4.5=serial_number"

    -dnsnames=<string>            Comma-separated list of subject alternative
                                  Names (SAN) domain names
    -emails=<string>              Comma-separated list of SAN email addresses
    -ips=<string>                 Comma-separated list of SAN IP addresses
    -uris=<string>                Comma-separated list of SAN URIs

    -ekus=<string>                Comma-separated list of extended key usage
                                  OIDs, e.g. "1.3.6.1.5.5.7.3.2"

    -template=<file>              Read values from the specified JSON-encoded
                                  file. Options specified at the command line
                                  override or append to the values in this
                                  template, as appropriate.
    -sampletemplate               Output an example template which can be
                                  modified and used with the -template option

Certificate and account information options:

  -retrieve=<serial>    Retrieve the previously-issued certificate with the
                        specified serial number
  -revoke=<serial>      Revoke the certificate with the specified serial number
  -rekey=<serial>       Reissue the certificate with the specified serial number
  -status=<serial>      Show the issued/revoked status for the certificate with
                        the specified serial number
  -updated=<serial>     Show the last-updated time for the certificate with the
                        specified serial number

  -certsissued          List the certificates issued during a specified time
                        window. See the "List-producing API options" section
                        below.
  -certsrevoked         List the certificates revoked during a specified time
                        window. See the "List-producing API options" section
                        below.
  -certsexpiring        List the certificates that expired or that will expire
                        during a specified time window. See the "List-producing
                        API options" section below.

  -countissued          Show the total count of certificates issued by this
                        HVCA account
  -countrevoked         Show the total count of certificates revoked by this
                        HVCA account
  -quota                Show the remaining quota of certificate issuances for
                        this HVCA account

  -trustchain           Show the chain of trust for certificates issued by this
                        HVCA account. The output is one or more PEM-encoded
                        certificates containing the root and any intermediate
                        Certificate Authority certificates.
  -policy               Show the validation policy for this HVCA account

Domain claim options:

  -claims               List all verified domain claims for this account. See
                        the "List-producing API options" section below.

      -pending          Used with -claims, list all pending rather than
                        verified domain claims

  -claimsubmit=<domain> Submit a new domain claim
  -claimretrieve=<id>   Show the details of the domain claim with the specified
                        ID
  -claimreassert=<id>   Reassert an existing domain claim, for example when the
                        assert-by time of the existing claim has passed
  -claimdelete=<id>     Delete the domain claim with the specified ID
  -claimdns=<id>        Request assertion of domain control using DNS for the
                        claim with the specified ID
  -claimhttp=<id>       Request assertion of domain control using HTTP for the
                        claim with the specified ID
      -scheme=<scheme>  Used with -claimhttp, specifies the protocol used to verify assertion of domain control
  -claimemail=<id>      Request assertion of domain control using Email for the
                        claim with the specified ID
      -address=<email>  Used with -claimemail, specifies the email address to send the verification email to verify assertion of domain control to.
  -claimemaillist=<id>  Get a list of emails authorized to perform email validation for the claim with the specified ID
  -authdomain=<authdomain> Used with -claimhttp and -claimsdns, specifies the authorization domain used to verify assertion of domain control

List-producing API options:

  A number of options listed above return a paginated list of results and a
  total count of items. The total count may be higher than the number of items
  shown if the total count is higher than the specified or maximum number of
  items per page. The remaining items may be retrieved by incrementing the page
  number in subsequent usages of the same option.

  The following options control the pagination:

  -from=<time>          The beginning of the time window, with a time format of
                        2016-01-02T15:04:05UTC. Defaults to 30 days prior to
                        the current time.
  -to=<time>            The end of the time window, with a time format of
                        2016-01-02T15:04:05UTC. Defaults to the current time.
  -since=<duration>     Used instead of -from and -to, this signifies a time
                        window from the specified duration in the past through
                        to the current time. The format is the same as for the
                        -duration option.

  -page=<int>           The page number. Defaults to 1
  -pagesize=<int>       The number of items per page. Defaults to 100.
  -totalcount           Show the total count of items in the population instead
                        of listing them.

Convenience options:

  -genrsa=<int>         Generate and output an RSA private key with the
                        specified bit size
  -encrypt              When used with -genrsa, prompt for a passphrase and
                        use it to encrypt the generated private key

Other options:

  -h                    Show this help page.
  -v                    Show version information.

`

var versionString = `HVClient 1.0

Usage: hvclient [options]

Copyright (c) 2019-2021 GMO GlobalSign Pte. Ltd.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
`

const sampleTemplate = `{
    "validity": {
        "not_before": 1477958400,
        "not_after": 1509494400
    },
    "subject_dn": {
        "country": "GB",
        "state": "London",
        "locality": "London",
        "street_address": "1 GlobalSign Road",
        "organization": "GMO GlobalSign",
        "organizational_unit": [
            "Operations",
            "Development"
        ],
        "common_name": "John Doe",
        "email": "john.doe@demo.hvca.globalsign.com",
        "jurisdiction_of_incorporation_locality_name": "London",
        "jurisdiction_of_incorporation_state_or_province_name": "London",
        "jurisdiction_of_incorporation_country_name": "United Kingdom",
        "business_category": "Internet security",
        "extra_attributes": [
            {
                "type": "2.5.4.4",
                "value": "Surname"
            }
        ]
    },
    "san": {
        "dns_names": [
            "test.demo.hvca.globalsign.com",
            "test2.demo.hvca.globalsign.com"
        ],
        "emails": [
            "admin@demo.hvca.globalsign.com",
            "contact@demo.hvca.globalsign.com"
        ],
        "ip_addresses": [
            "198.41.214.154"
        ],
        "uris": [
            "http://test.demo.hvca.globalsign.com/uri"
        ],
        "other_names": [
            {
                "type": "1.3.6.1.4.1.311.20.2.3",
                "value": "upn@demo.hvca.globalsign.com"
            }
        ]
    },
    "extended_key_usages": [
        "1.3.6.1.5.5.7.3.1",
        "1.3.6.1.5.5.7.3.2"
    ],
    "subject_da": {
        "gender": "m",
        "date_of_birth": "1979-01-31",
        "place_of_birth": "London",
        "country_of_citizenship": [
            "GB",
            "US"
        ],
        "country_of_residence": [
            "US"
        ],
        "extra_attributes": [
            {
                "type": "2.5.29.9.1.1.1"
            },
            {
                "type": "2.5.29.9.1.1.2",
                "value": "custom subject da value"
            }
        ]
    },
    "qualified_statements": {
        "semantics": {
            "identifier": "1.1.1.1.1.1",
            "name_authorities": [
                "contact@ra1.hvsign.globalsign.com"
            ]
        },
        "etsi_qc_compliance": true,
        "etsi_qc_sscd_compliance": true,
        "etsi_qc_type": "0.4.0.1862.1.6.1",
        "etsi_qc_retention_period": 1,
        "etsi_qc_pds": {
            "EN": "https://demo.hvsign.globalsign.com/en/pds",
            "RU": "https://demo.hvsign.globalsign.com/ru/pds"
        }
    },
    "ms_extension_template": {
        "id": "1.2.3.4",
        "major_version": 3,
        "minor_version": 7
    },
    "custom_extensions": {
        "2.5.29.99.1": "NIL",
        "2.5.29.99.2": "SOME TEXT"
    }
}
`

// showHelp outputs online help documentation.
func showHelp() {
	fmt.Print(helpDoc)
}

// showVersion outputs version and copyright information.
func showVersion() {
	fmt.Print(versionString)
}

// showSampleTemplate outputs a sample certificate request template.
func showSampleTemplate() {
	fmt.Print(sampleTemplate)
}
