# hvclient

Package hvclient provides an interface for making HVCA API calls.

Comprehensive examples of using this package to make HVCA API calls may be found
in the accompanying hvclient commandline utility included in this repository,
and in the test examples.

## Testing

Most of the unit tests may be run with `go test` in the usual way.

Running the integration tests with `go test -tags integration` requires:

1. an HVCA account;

2. various configuration files; and

3. a certificate/key pair for the TLS connection

The following environment variables should be set, and should contain the
path of test configuration files with the stated property:

* `HVCLIENT_TEST_CONFIG_PKCS8` - HVCA account with PKCS#8 proof-of-possession
* `HVCLIENT_TEST_CONFIG_PKCS10` - HVCA account with PKCS#10 proof-of-possession
* `HVCLIENT_TEST_CONFIG_ENCRYPTED_KEY` - same as `HVCLIENT_TEST_CONFIG_PKCS8`,
but with an encrypted private key file
* `HVCLIENT_TEST_CONFIG_BAD_API_CREDS` - with a valid mTLS certificate and
private key, but an invalid API key/secret

The configuration files and the certificate/key pairs are not included in the
repository. Moreover, many of the integration tests are written to expect
values from a particular HVCA test account, and would need to be modified
to pass with a different account.

## Quickstart Guide

Basic usage is straightforward:

1. Create a `Client` object

2. Use it to make HVCA API calls.

Creating a `Client` object requires:

1. An API key and API secret provided by GlobalSign at account set-up

2. A private key and a certificate to use for mutual TLS authentication
with the HVCA server. The private key should be the one associated with
the public key that was provided to GlobalSign at account set-up, and the
certificate should be the one provided by GlobalSign along with the API
key and API secret.

The `Client` object may be created with either:

1. A configuration file, useful when the account credentials are located in
files; or

2. A `Config` object, useful when the account credentials are obtained
programmatically from a secrets vault, from environment variables, or in some
other manner.

Refer to the documentation below for the `Config` object for specifications of
the configuration file format and the `Config` object itself.

Most of the API calls are simple and mostly self-explanatory. Refer to the
documentation below. Like many modern APIs, each call takes a Go context,
primarily to control the timeout for network requests.

Requesting a certificate requires the creation of a `Request` object. This can
be as simple as:

```go
var req = hvclient.Request{
	Validity: &hvclient.Validity{
		NotBefore: time.Now(),
		NotAfter:  time.Unix(0, 0),
	},
	Subject: &hvclient.DN{
		CommonName: "John Doe",
    },
    PrivateKey: key,
}
```

or as complicated as:

```go
var req = hvclient.Request{
	Validity: &hvclient.Validity{
		NotBefore: time.Now(),
		NotAfter:  time.Unix(0, 0),
	},
	Subject: &hvclient.DN{
		CommonName:    "John Doe",
		Country:       "GB",
		State:         "London",
		Locality:      "London",
		StreetAddress: "1 GlobalSign Road",
		Organization:  "GMO GlobalSign",
		OrganizationalUnit: []string{
			"Operations",
			"Development",
		},
		Email:            "john.doe@demo.hvca.globalsign.com",
		JOILocality:      "London",
		JOIState:         "London",
		JOICountry:       "United Kingdom",
		BusinessCategory: "Internet security",
		ExtraAttributes: []hvclient.OIDAndString{
			{
				OID:   asn1.ObjectIdentifier{2, 5, 4, 4},
				Value: "Surname",
			},
		},
	},
	SAN: &hvclient.SAN{
		DNSNames: []string{
			"test.demo.hvca.globalsign.com",
			"test2.demo.hvca.globalsign.com",
		},
		Emails: []string{
			"admin@demo.hvca.globalsign.com",
			"contact@demo.hvca.globalsign.com",
		},
		IPAddresses: []net.IP{
			net.ParseIP("198.41.214.154"),
		},
		URIs: []*url.URL{
			mustParseURI("http://test.demo.hvca.globalsign.com/uri"),
		},
		OtherNames: []hvclient.OIDAndString{
			{
				OID:   asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3},
				Value: "upn@demo.hvca.globalsign.com",
			},
		},
	},
	EKUs: []asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7, 3, 1},
		{1, 3, 6, 1, 5, 5, 7, 3, 2},
	},
	DA: &hvclient.DA{
		Gender:               "m",
		DateOfBirth:          time.Date(1979, 1, 31, 12, 0, 0, 0, time.UTC),
		PlaceOfBirth:         "London",
		CountryOfCitizenship: []string{"GB", "US"},
		CountryOfResidence:   []string{"US"},
		ExtraAttributes: []hvclient.OIDAndString{
			{
				OID: asn1.ObjectIdentifier{2, 5, 29, 9, 1, 1, 1},
			},
			{
				OID:   asn1.ObjectIdentifier{2, 5, 29, 9, 1, 1, 2},
				Value: "custom subject da value",
			},
		},
	},
	QualifiedStatements: &hvclient.QualifiedStatements{
		Semantics: hvclient.Semantics{
			OID:             asn1.ObjectIdentifier{1, 1, 1, 1, 1, 1},
			NameAuthorities: []string{"contact@ra1.hvsign.globalsign.com"},
		},
		QCCompliance:      true,
		QCSSCDCompliance:  true,
		QCType:            asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 1},
		QCRetentionPeriod: 1,
		QCPDs: map[string]string{
			"EN": "https://demo.hvsign.globalsign.com/en/pds",
			"RU": "https://demo.hvsign.globalsign.com/ru/pds",
		},
	},
	MSExtension: &hvclient.MSExtension{
		OID:          asn1.ObjectIdentifier{1, 2, 3, 4},
		MajorVersion: 3,
		MinorVersion: 7,
	},
	CustomExtensions: []hvclient.OIDAndString{
		{
			OID:   asn1.ObjectIdentifier{2, 5, 29, 99, 1},
			Value: "NIL",
		},
		{
			OID:   asn1.ObjectIdentifier{2, 5, 29, 99, 2},
			Value: "SOME TEXT",
		},
	},
    CSR: csr,
}
```

where `key` and `csr` are programmatically obtained private key and
`x509.CertificateRequest` objects, respectively. `Request` objects are fully
serializable to and from JSON, so a `Request` object may initialized from
a JSON template, and then modified as necessary (e.g. to set the not-before
and not-after times, the public key as described below, and any other
request-specific fields).

With respect to proving possession of the private key corresponding to the
public key to be included in the certificate, an HVCA account may be set up
in one of three ways:

1. No proof required - in this case, assign the public key to the `PublicKey`
field of the `Request` object.

2. Proof by signing the public key with the private key - in this case, assign
the private key to the `PrivateKey` field of the `Request` object, and the
public key will be automatically extracted and the signature automatically
computed.

3. Proof via a signed PKCS#10 certificate signing request - in this case,
assign the `x509.CertificateRequest` object to the `CSR` field of the `Request`
object. Note that in this case, HVCA ignores all the fields in the PKCS#10 CSR
except for the public key and the signature, and so any fields in the CSR which
should be included in the certificate will need to be manually copied into the
`Request` object.

### Examples

Some basic examples of usage follow.

#### Requesting a new certificate

```go
// Generate a new key for the requested certificate.

key, err := rsa.GenerateKey(rand.Reader, 2048)
if err != nil {
    log.Fatalf("couldn't generate key: %v", err)
}

// Create context for API requests with a reasonable timeout.

ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
defer cancel()

// Create new HVCA client.

hv, err := hvclient.NewClient(
    ctx,
    &hvclient.Config{
        URL:       "https://emea.api.hvca.globalsign.com:8443/v2",
        APIKey:    apikey,
        APISecret: apisecret,
        TLSKey:    tlsPrivateKey,
        TLSCert:   tlsCertificate,
    },
)
if err != nil {
    log.Fatalf("couldn't create HVCA client: %v", err)
}

// Request certificate.

serialNumber, err := hv.CertificateRequest(
    ctx,
    &hvclient.Request{
        Validity: &hvclient.Validity{
            NotBefore: time.Now(),
            NotAfter:  time.Unix(0, 0),
        },
        Subject: &hvclient.DN{
            CommonName:         "John Doe",
            OrganizationalUnit: []string{"Finance", "Complaints"},
        },
        PublicKey: key.PublicKey,
    },
)
if err != nil {
    log.Fatalf("certificate request failed: %v", err)
}

// Retrieve certificate by serial number.

certInfo, err := hv.CertificateRetrieve(ctx, serialNumber)
if err != nil {
    log.Fatalf("certificate retrieval failed: %v", err)
}

// Parse returned PEM-encoded certificate into an x509.Certificate structure.

block, _ := pem.Decode([]byte(certInfo.PEM))
cert, err := x509.ParseCertificate(block.Bytes)
if err != nil {
    log.Fatalf("couldn't parse certificate: %v", err)
}

// Output some details from the issued and parsed certificate.

fmt.Printf("Issued certificate subject common name: %s\n", cert.Subject.CommonName)
fmt.Printf("Issued certificate subject organizational unit: %v\n", cert.Subject.OrganizationalUnit)

// Output:
// Issued certificate subject common name: John Doe
// Issued certificate subject organizational unit: [Finance Complaints]
```

#### Counting certificates issued

```go
// Create context for API request with a reasonable timeout.

ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
defer cancel()

// Create new HVCA client.

hv, err := hvclient.NewClient(
    ctx,
    &hvclient.Config{
        URL:       "https://emea.api.hvca.globalsign.com:8443/v2",
        APIKey:    apikey,
        APISecret: apisecret,
        TLSKey:    tlsPrivateKey,
        TLSCert:   tlsCertificate,
    },
)
if err != nil {
    log.Fatalf("couldn't create HVCA client: %v", err)
}

// Request count of certificates issued from this account.

count, err := hv.CounterCertsIssued(ctx)
if err != nil {
    log.Fatalf("couldn't get count of certificates issued: %v", err)
}

// Output a message based on the count.

if count > 100 {
    fmt.Print("More than 100 certificates issued from this account.\n")
} else {
    fmt.Print("100 or less certificates issued from this account.\n")
}

// Output:
// More than 100 certificates issued from this account.
```

#### Getting certificates issued statistics

```go
// Create context for API request with a reasonable timeout.

ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
defer cancel()

// Create new HVCA client.

hv, err := hvclient.NewClient(
    ctx,
    &hvclient.Config{
        URL:       "https://emea.api.hvca.globalsign.com:8443/v2",
        APIKey:    apikey,
        APISecret: apisecret,
        TLSKey:    tlsPrivateKey,
        TLSCert:   tlsCertificate,
    },
)
if err != nil {
    log.Fatalf("couldn't create HVCA client: %v", err)
}

// Request statistics for certificates issued during the specified time
// window.

stats, totalcount, err := hv.StatsIssued(
    ctx,
    1,
    100,
    time.Date(2018, 10, 5, 14, 10, 0, 0, time.UTC),
    time.Date(2018, 10, 5, 14, 23, 20, 0, time.UTC),
)
if err != nil {
    log.Fatalf("couldn't get statistics of certificates issued: %v", err)
}

// Output serial numbers of certificates issued during the time window.

for n, stat := range stats {
    fmt.Printf("%d: %s\n", n+1, stat.SerialNumber)
}
fmt.Printf("Total count: %d\n", totalcount)

// Output:
// 1: 01CFABDF1EBA6325930BF8B6FFD89F12
// 2: 01F61750041A52E5561F0DC342A4BF3D
// 3: 01BE04ABA4D398ABA21D3C6E56274D18
// 4: 0120706646DB29EDC8F168F76ACE65C1
// Total count: 4
```

## Usage

#### type APIError

```go
type APIError struct {
	StatusCode  int    // HTTP status code returned by HVCA
	Description string // Description of the error
}
```

APIError is an error returned by the HVCA HTTP API

#### func (APIError) Error

```go
func (e APIError) Error() string
```
Error returns a string representation of the error.

#### type CertInfo

```go
type CertInfo struct {
	PEM       string            // The PEM-encoded certificate
	X509      *x509.Certificate // The parsed certificate
	Status    CertStatus        // Issued or revoked
	UpdatedAt time.Time         // When the certificate was last updated
}
```

CertInfo contains a certificate and associated information as returned by an
HVCA GET /certificates/{certificate} API call.

#### func (CertInfo) Equal

```go
func (s CertInfo) Equal(other CertInfo) bool
```
Equal checks if two certificate metadata objects are equivalent.

#### func (CertInfo) MarshalJSON

```go
func (s CertInfo) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of certificate metadata.

#### func (*CertInfo) UnmarshalJSON

```go
func (s *CertInfo) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses JSON-encoded certificate metadata and stores the result in
the object.

#### type CertMeta

```go
type CertMeta struct {
	SerialNumber string    // Certificate serial number
	NotBefore    time.Time // Certificate not valid before this time
	NotAfter     time.Time // Certificate not valid after this time
}
```

CertMeta is the certificate metadata returned by one of the HVCA GET /stats API
calls.

#### func (CertMeta) Equal

```go
func (c CertMeta) Equal(other CertMeta) bool
```
Equal checks if two certificate metadata objects are equivalent.

#### func (CertMeta) MarshalJSON

```go
func (c CertMeta) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a certificate metadata object.

#### func (*CertMeta) UnmarshalJSON

```go
func (c *CertMeta) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded certificate metadata object and stores the
result in the object.

#### type CertStatus

```go
type CertStatus int
```

CertStatus is the issued/revoked status of a certificate.

```go
const (
	StatusIssued CertStatus = iota + 1
	StatusRevoked
)
```
Certificate status values.

#### func (CertStatus) MarshalJSON

```go
func (s CertStatus) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a certificate status value.

#### func (CertStatus) String

```go
func (s CertStatus) String() string
```
String returns a description of the certificate status.

#### func (*CertStatus) UnmarshalJSON

```go
func (s *CertStatus) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded certificate status value and stores the
result in the object.

#### type Claim

```go
type Claim struct {
	ID        string          // Claim ID
	Status    ClaimStatus     // Pending or verified
	Domain    string          // The domain being claimed
	CreatedAt time.Time       // Time this claim was created
	ExpiresAt time.Time       // Time this claim expires
	AssertBy  time.Time       // Time by which this claim must be asserted
	Log       []ClaimLogEntry // List of verification log entries for the claim
}
```

Claim is a domain claim, as returned by a /claims/domains/{claimID} API call.

#### func (Claim) Equal

```go
func (c Claim) Equal(other Claim) bool
```
Equal checks if two domain claims are equivalent.

#### func (Claim) MarshalJSON

```go
func (c Claim) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a domain claim and stores the result in
the object.

#### func (*Claim) UnmarshalJSON

```go
func (c *Claim) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded domain claim and stores the result in the
object.

#### type ClaimAssertionInfo

```go
type ClaimAssertionInfo struct {
	Token    string    // Token to be used for the assertion
	AssertBy time.Time // Time by which this claim must be asserte
	ID       string    // ID of the claim
}
```

ClaimAssertionInfo is the response from a /claims/domains API call.

#### func (ClaimAssertionInfo) Equal

```go
func (c ClaimAssertionInfo) Equal(other ClaimAssertionInfo) bool
```
Equal checks if two domain claim assertion info objects are equivalent.

#### func (ClaimAssertionInfo) MarshalJSON

```go
func (c ClaimAssertionInfo) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a domain claim assertion info object.

#### func (*ClaimAssertionInfo) UnmarshalJSON

```go
func (c *ClaimAssertionInfo) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded domain claim assertion info object and
stores the result in the object.

#### type ClaimLogEntry

```go
type ClaimLogEntry struct {
	Status      ClaimLogEntryStatus // Success or error
	Description string              // Log entry description
	TimeStamp   time.Time           // Time of log entry
}
```

ClaimLogEntry is a domain claim verification log entry.

#### func (ClaimLogEntry) Equal

```go
func (l ClaimLogEntry) Equal(other ClaimLogEntry) bool
```
Equal checks if two domain claim verification log entries are equivalent.

#### func (ClaimLogEntry) MarshalJSON

```go
func (l ClaimLogEntry) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a domain claim verification log entry.

#### func (*ClaimLogEntry) UnmarshalJSON

```go
func (l *ClaimLogEntry) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded domain claim verification log entry and
stores the result in the object.

#### type ClaimLogEntryStatus

```go
type ClaimLogEntryStatus int
```

ClaimLogEntryStatus is the success/error status of a domain claim verification
log entry.

```go
const (
	VerificationSuccess ClaimLogEntryStatus = iota + 1
	VerificationError
)
```
Claim log entry status constants.

#### func (ClaimLogEntryStatus) MarshalJSON

```go
func (s ClaimLogEntryStatus) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a domain claim verification log entry
status value.

#### func (ClaimLogEntryStatus) String

```go
func (s ClaimLogEntryStatus) String() string
```
String returns a description of the claim status.

#### func (*ClaimLogEntryStatus) UnmarshalJSON

```go
func (s *ClaimLogEntryStatus) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded domain claim verification log entry status
value and stores the result in the object.

#### type ClaimStatus

```go
type ClaimStatus int
```

ClaimStatus is the pending/verified status of a domain claim.

```go
const (
	StatusPending ClaimStatus = iota + 1
	StatusVerified
)
```
Domain claim status constants.

#### func (ClaimStatus) MarshalJSON

```go
func (s ClaimStatus) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a claim status value.

#### func (ClaimStatus) String

```go
func (s ClaimStatus) String() string
```
String returns a description of the claim status.

#### func (*ClaimStatus) UnmarshalJSON

```go
func (s *ClaimStatus) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded claim status value and stores the result in
the object.

#### type Client

```go
type Client struct {
}
```

Client is a fully-featured client through which HVCA API calls can be made.

A client is created from either a configuration object or a configuration file
containing the account and other information. Once a client is created, it can
then be used to make HVCA API calls.

The user does not need to explicitly login. The client object will log the user
in automatically, and refresh their login if the authentication token expires.
In the event of a HTTP 503 service unavailable response, or a response
indicating that a request has been accepted but the corresponding resource is
not yet available, the client will automatically wait and retry the call a
predetermined number of times. The maximum wait time for this process may be
controlled through the context passed to each API call.

It is safe to make concurrent API calls from a single client object.

#### func  NewClient

```go
func NewClient(ctx context.Context, conf *Config) (*Client, error)
```
NewClient creates a new HVCA client from a configuration object. An initial
login is made, and the returned client is immediately ready to make API calls.

#### func  NewClientFromFile

```go
func NewClientFromFile(ctx context.Context, filename string) (*Client, error)
```
NewClientFromFile returns a new HVCA client from a configuration file. An
initial login is made, and the returned client is immediately ready to make API
calls.

Refer to the documentation for the Config object for the format of the
configuration file.

#### func (*Client) CertificateRequest

```go
func (c *Client) CertificateRequest(ctx context.Context, hvcareq *Request) (string, error)
```
CertificateRequest requests a new certificate based on a Request object. The
HVCA HTTP API is asynchronous, and on success this method returns the serial
number of the certificate to be issued. After a short delay, the certificate
itself may be retrieved via the CertificateRetrieve method.

#### func (*Client) CertificateRetrieve

```go
func (c *Client) CertificateRetrieve(ctx context.Context, serialNumber string) (*CertInfo, error)
```
CertificateRetrieve retrieves the certificate with the specified serial number.

#### func (*Client) CertificateRevoke

```go
func (c *Client) CertificateRevoke(ctx context.Context, serialNumber string) error
```
CertificateRevoke revokes the certificate with the specified serial number.

#### func (*Client) ClaimDNS

```go
func (c *Client) ClaimDNS(ctx context.Context, id string) (bool, error)
```
ClaimDNS requests assertion of domain control using DNS once the appropriate
token has been placed in the relevant DNS records. A return value of false
indicates that the assertion request was created. A return value of true
indicates that domain control was verified.

#### func (*Client) ClaimDelete

```go
func (c *Client) ClaimDelete(ctx context.Context, id string) error
```
ClaimDelete deletes the domain claim with the specified ID.

#### func (*Client) ClaimReassert

```go
func (c *Client) ClaimReassert(ctx context.Context, id string) (*ClaimAssertionInfo, error)
```
ClaimReassert reasserts an existing domain claim, for example if the assert-by
time of a previous assertion request has expired.

#### func (*Client) ClaimRetrieve

```go
func (c *Client) ClaimRetrieve(ctx context.Context, id string) (*Claim, error)
```
ClaimRetrieve returns the domain claim with the specified ID.

#### func (*Client) ClaimSubmit

```go
func (c *Client) ClaimSubmit(ctx context.Context, domain string) (*ClaimAssertionInfo, error)
```
ClaimSubmit submits a new domain claim and returns the token value that should
be used to verify control of that domain.

#### func (*Client) ClaimsDomains

```go
func (c *Client) ClaimsDomains(ctx context.Context, page, perPage int, status ClaimStatus) ([]Claim, int64, error)
```
ClaimsDomains returns a slice of either pending or verified domain claims along
with the total count of domain claims in either category. The total count may be
higher than the number of claims in the slice if the total count is higher than
the specified number of claims per page. The HVCA API enforces a maximum number
of claims per page. If the total count is higher than the number of claims in
the slice, the remaining claims may be retrieved by incrementing the page number
in subsequent calls of this method.

#### func (*Client) CounterCertsIssued

```go
func (c *Client) CounterCertsIssued(ctx context.Context) (int64, error)
```
CounterCertsIssued returns the number of certificates issued by the calling
account.

#### func (*Client) CounterCertsRevoked

```go
func (c *Client) CounterCertsRevoked(ctx context.Context) (int64, error)
```
CounterCertsRevoked returns the number of certificates revoked by the calling
account.

#### func (*Client) DefaultTimeout

```go
func (c *Client) DefaultTimeout() time.Duration
```
DefaultTimeout returns the timeout specified in the configuration object or file
used to create the client, or the default timeout provided if no value was
specified. This is useful for honoring the timeout requested by the
configuration when creating the context to pass to an API method if the original
configuration information is no longer available.

#### func (*Client) Policy

```go
func (c *Client) Policy(ctx context.Context) (*Policy, error)
```
Policy returns the calling account's validation policy.

#### func (*Client) QuotaIssuance

```go
func (c *Client) QuotaIssuance(ctx context.Context) (int64, error)
```
QuotaIssuance returns the remaining quota of certificate issuances for the
calling account.

#### func (*Client) StatsExpiring

```go
func (c *Client) StatsExpiring(
	ctx context.Context,
	page, perPage int,
	notBefore, notAfter time.Time,
) ([]CertMeta, int64, error)
```
StatsExpiring returns a slice of the certificates which expired or which will
expire during the specified time window, along with the total count of those
certificates. The total count may be higher than the number of certificate in
the slice if the total count is higher than the specified number of certificates
per page. The HVCA API enforces a maximum number of certificates per page. If
the total count is higher than the number of certificates in the slice, the
remaining certificates may be retrieved by incrementing the page number in
subsequent calls of this method.

#### func (*Client) StatsIssued

```go
func (c *Client) StatsIssued(
	ctx context.Context,
	page, perPage int,
	notBefore, notAfter time.Time,
) ([]CertMeta, int64, error)
```
StatsIssued returns a slice of the certificates which were issued during the
specified time window, along with the total count of those certificates. The
total count may be higher than the number of certificate in the slice if the
total count is higher than the specified number of certificates per page. The
HVCA API enforces a maximum number of certificates per page. If the total count
is higher than the number of certificates in the slice, the remaining
certificates may be retrieved by incrementing the page number in subsequent
calls of this method.

#### func (*Client) StatsRevoked

```go
func (c *Client) StatsRevoked(
	ctx context.Context,
	page, perPage int,
	notBefore, notAfter time.Time,
) ([]CertMeta, int64, error)
```
StatsRevoked returns a slice of the certificates which were revoked during the
specified time window, along with the total count of those certificates. The
total count may be higher than the number of certificate in the slice if the
total count is higher than the specified number of certificates per page. The
HVCA API enforces a maximum number of certificates per page. If the total count
is higher than the number of certificates in the slice, the remaining
certificates may be retrieved by incrementing the page number in subsequent
calls of this method.

#### func (*Client) TrustChain

```go
func (c *Client) TrustChain(ctx context.Context) ([]string, error)
```
TrustChain returns the chain of trust for the certificates issued by the calling
account.

#### type Config

```go
type Config struct {

	// URL is the URL of the HVCA service, including any version number.
	URL string

	// TLSCert is the certificate to use for mutual TLS authentication to HVCA,
	// provided by GlobalSign when the HVCA account was set up.
	TLSCert *x509.Certificate

	// TLSKey is the private key corresponding to the public key provided to
	// GlobalSign when the HVCA account was set up. This is used for mutual TLS
	// authentication with HVCA, and is NOT related to any public key to be
	// included in a certificate request.
	TLSKey interface{}

	// APIKey is the API key for the HVCA account, provided by GlobalSign when
	// the account was set up.
	APIKey string

	// APISecret is the API secret for the HVCA account, provided by GlobalSign
	// when the account was set up.
	APISecret string

	// Timeout is the number of seconds to wait before cancelling an HVCA API
	// request. If this is omitted or set to zero, a reasonable default will
	// be used.
	Timeout time.Duration
}
```

Config is a configuration object for an HVCA client.

#### func  NewConfigFromFile

```go
func NewConfigFromFile(filename string) (*Config, error)
```
NewConfigFromFile creates a new HVCA client configuration object from a
configuration file.

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

#### func (*Config) Validate

```go
func (c *Config) Validate() error
```
Validate returns an error if any fields in the configuration object are missing
or malformed. It also calculates a default timeout, if the Timeout field is
zero.

#### type CustomExtensionsPolicy

```go
type CustomExtensionsPolicy struct {
	OID         asn1.ObjectIdentifier `json:"-"`
	Presence    Presence              `json:"presence"`
	Critical    bool                  `json:"critical"`
	ValueType   ValueType             `json:"value_type"`
	ValueFormat string                `json:"value_format,omitempty"`
}
```

CustomExtensionsPolicy is the custom extensions field in a validation policy.

#### type DA

```go
type DA struct {
	Gender               string
	DateOfBirth          time.Time
	PlaceOfBirth         string
	CountryOfCitizenship []string
	CountryOfResidence   []string
	ExtraAttributes      []OIDAndString
}
```

DA is a list of Subject Directory Attributes to include in a certificate. See
RFC 3739.

#### func (*DA) Equal

```go
func (d *DA) Equal(other *DA) bool
```
Equal checks if two subject directory attributes lists are equivalent.

#### func (*DA) MarshalJSON

```go
func (d *DA) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a subject directory attributes list.

#### func (*DA) UnmarshalJSON

```go
func (d *DA) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded subject directory attributes list and stores
the result in the object.

#### type DN

```go
type DN struct {
	Country            string         `json:"country,omitempty"`
	State              string         `json:"state,omitempty"`
	Locality           string         `json:"locality,omitempty"`
	StreetAddress      string         `json:"street_address,omitempty"`
	Organization       string         `json:"organization,omitempty"`
	OrganizationalUnit []string       `json:"organizational_unit,omitempty"`
	CommonName         string         `json:"common_name,omitempty"`
	Email              string         `json:"email,omitempty"`
	JOILocality        string         `json:"jurisdiction_of_incorporation_locality_name,omitempty"`
	JOIState           string         `json:"jurisdiction_of_incorporation_state_or_province_name,omitempty"`
	JOICountry         string         `json:"jurisdiction_of_incorporation_country_name,omitempty"`
	BusinessCategory   string         `json:"business_category,omitempty"`
	ExtraAttributes    []OIDAndString `json:"extra_attributes,omitempty"`
}
```

DN is a list of Distinguished Name attributes to include in a certificate. See
RFC 5280 #4.1.2.6.

#### func (*DN) Equal

```go
func (n *DN) Equal(other *DN) bool
```
Equal checks if two subject distinguished names are equivalent.

#### func (*DN) PKIXName

```go
func (n *DN) PKIXName() pkix.Name
```
PKIXName converts a subject distinguished name into a pkix.Name object.

#### type EKUPolicy

```go
type EKUPolicy struct {
	EKUs     ListPolicy `json:"ekus"`
	Critical bool       `json:"critical"`
}
```

EKUPolicy is the extended key usages field in a validation policy.

#### type ETSIPDsPolicy

```go
type ETSIPDsPolicy struct {
	Presence Presence          `json:"presence"`
	Policies map[string]string `json:"policies"`
}
```

ETSIPDsPolicy is the PKI disclosure statements field in the qualified statements
field in a validation policy.

#### type IntegerPolicy

```go
type IntegerPolicy struct {
	Presence Presence `json:"presence"`
	Min      int64    `json:"min"`
	Max      int64    `json:"max"`
}
```

IntegerPolicy is an integer value entry in a validation policy.

#### type KeyFormat

```go
type KeyFormat int
```

KeyFormat is the allowed format of a public key.

```go
const (
	PKCS8 KeyFormat = iota + 1
	PKCS10
)
```
Key format value constants.

#### func (KeyFormat) MarshalJSON

```go
func (f KeyFormat) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a key format value.

#### func (KeyFormat) String

```go
func (f KeyFormat) String() string
```
String returns a description of the key format value.

#### func (*KeyFormat) UnmarshalJSON

```go
func (f *KeyFormat) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded key format value and stores the result in
the object.

#### type KeyType

```go
type KeyType int
```

KeyType is the type of a public key.

```go
const (
	RSA KeyType = iota + 1
	ECDSA
)
```
Key type value constants.

#### func (KeyType) MarshalJSON

```go
func (t KeyType) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a key type value.

#### func (KeyType) String

```go
func (t KeyType) String() string
```
String returns a description of the key type value.

#### func (*KeyType) UnmarshalJSON

```go
func (t *KeyType) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded key type value and stores the result in the
object.

#### type ListPolicy

```go
type ListPolicy struct {
	Static   bool     `json:"static"`
	List     []string `json:"list"`
	MinCount int      `json:"mincount"`
	MaxCount int      `json:"maxcount"`
}
```

ListPolicy is a list value entry in a validation policy.

#### type MSExtension

```go
type MSExtension struct {
	OID          asn1.ObjectIdentifier
	MajorVersion int
	MinorVersion int
}
```

MSExtension contains values to populate a Microsoft template extension
(91.3.6.1.4.1.311.21.7) with.

#### func (*MSExtension) Equal

```go
func (m *MSExtension) Equal(other *MSExtension) bool
```
Equal checks if two MS template extensions are equivalent.

#### func (*MSExtension) MarshalJSON

```go
func (m *MSExtension) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a MS template extension.

#### func (*MSExtension) UnmarshalJSON

```go
func (m *MSExtension) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded MS template extension and stores the result
in the object.

#### type MSExtensionTemplatePolicy

```go
type MSExtensionTemplatePolicy struct {
	Critical     bool           `json:"critical"`
	TemplateID   *StringPolicy  `json:"template_id,omitempty"`
	MajorVersion *IntegerPolicy `json:"major_version,omitempty"`
	MinorVersion *IntegerPolicy `json:"minor_version,omitempty"`
}
```

MSExtensionTemplatePolicy is the Microsoft template extension field in a
validation policy.

#### type OIDAndString

```go
type OIDAndString struct {
	OID   asn1.ObjectIdentifier
	Value string
}
```

OIDAndString is an ASN.1 object identifier (OID) together with an associated
string value.

#### func (OIDAndString) AttributeTypeAndValue

```go
func (o OIDAndString) AttributeTypeAndValue() pkix.AttributeTypeAndValue
```
AttributeTypeAndValue converts an OIDAndString object into a
pkix.AttributeTypeAndValue object.

#### func (OIDAndString) Equal

```go
func (o OIDAndString) Equal(other OIDAndString) bool
```
Equal checks if two OID and string objects are equivalent.

#### func (OIDAndString) MarshalJSON

```go
func (o OIDAndString) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of an OID and string.

#### func (*OIDAndString) UnmarshalJSON

```go
func (o *OIDAndString) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded OID and string and stores the result in the
object.

#### type OptionalStaticPresence

```go
type OptionalStaticPresence int
```

OptionalStaticPresence denotes whether a static boolean is optional, or true, or
false.

```go
const (
	StaticOptional OptionalStaticPresence = iota + 1
	StaticTrue
	StaticFalse
)
```
Optional static presence values.

#### func (OptionalStaticPresence) MarshalJSON

```go
func (v OptionalStaticPresence) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of an optional static presence value.

#### func (OptionalStaticPresence) String

```go
func (v OptionalStaticPresence) String() string
```
String returns a description of the optional static presence value.

#### func (*OptionalStaticPresence) UnmarshalJSON

```go
func (v *OptionalStaticPresence) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded optional static presence value and stores
the result in the object.

#### type Policy

```go
type Policy struct {
	Validity            *ValidityPolicy
	SubjectDN           *SubjectDNPolicy
	SAN                 *SANPolicy
	EKUs                *EKUPolicy
	SubjectDA           *SubjectDAPolicy
	QualifiedStatements *QualifiedStatementsPolicy
	MSExtensionTemplate *MSExtensionTemplatePolicy
	CustomExtensions    []CustomExtensionsPolicy
	PublicKey           *PublicKeyPolicy
	PublicKeySignature  Presence
}
```

Policy is a certificate request validation policy.

#### func (Policy) MarshalJSON

```go
func (p Policy) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a validation policy.

#### func (*Policy) UnmarshalJSON

```go
func (p *Policy) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded validation policy and stores the result in
the object.

#### type Presence

```go
type Presence int
```

Presence is the presence field in a validation policy.

```go
const (
	Optional Presence = iota + 1
	Required
	Forbidden
	Static
)
```
Presence value constants.

#### func (Presence) MarshalJSON

```go
func (p Presence) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a presence value.

#### func (Presence) String

```go
func (p Presence) String() string
```
String returns a description of the presence value.

#### func (*Presence) UnmarshalJSON

```go
func (p *Presence) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded presence value and stores the result in the
object.

#### type PublicKeyPolicy

```go
type PublicKeyPolicy struct {
	KeyType        KeyType   `json:"key_type"`
	AllowedLengths []int     `json:"allowed_lengths"`
	KeyFormat      KeyFormat `json:"key_format"`
}
```

PublicKeyPolicy is the public key field in a validation policy.

#### type QualifiedStatements

```go
type QualifiedStatements struct {
	Semantics         Semantics
	QCCompliance      bool
	QCSSCDCompliance  bool
	QCType            asn1.ObjectIdentifier
	QCRetentionPeriod int
	QCPDs             map[string]string
}
```

QualifiedStatements is a list of qualified statements to include in a
certificate. See RFC 3739 #3.2.6.

#### func (*QualifiedStatements) Equal

```go
func (q *QualifiedStatements) Equal(other *QualifiedStatements) bool
```
Equal checks if two qualified statements lists are equivalent.

#### func (*QualifiedStatements) MarshalJSON

```go
func (q *QualifiedStatements) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a qualified statements list.

#### func (*QualifiedStatements) UnmarshalJSON

```go
func (q *QualifiedStatements) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded qualified statements list and stores the
result in the object.

#### type QualifiedStatementsPolicy

```go
type QualifiedStatementsPolicy struct {
	Semantics             *SemanticsPolicy       `json:"semantics"`
	ETSIQCCompliance      OptionalStaticPresence `json:"etsi_qc_compliance"`
	ETSIQCSSCDCompliance  OptionalStaticPresence `json:"etsi_qc_sscd_compliance"`
	ETSIQCType            *StringPolicy          `json:"etsi_qc_type"`
	ETSIQCRetentionPeriod *IntegerPolicy         `json:"etsi_qc_retention_period"`
	ETSIQCPDs             *ETSIPDsPolicy         `json:"etsi_qc_pds"`
}
```

QualifiedStatementsPolicy is the qualified statements field in a validation
policy.

#### type Request

```go
type Request struct {
	Validity            *Validity
	Subject             *DN
	SAN                 *SAN
	EKUs                []asn1.ObjectIdentifier
	DA                  *DA
	QualifiedStatements *QualifiedStatements
	MSExtension         *MSExtension
	CustomExtensions    []OIDAndString
	CSR                 *x509.CertificateRequest
	PrivateKey          interface{}
	PublicKey           interface{}
}
```

Request is a request to HVCA for the issuance of a new certificate.

An HVCA account will be set up with one of three options regarding
proof-of-possession of the private key corresponding to the public key to be
included in the certificate:

1. No proof required

2. Provide the public key signed by the private key

3. Provide a signed PKCS#10 certificate signing request.

For case 1, simply assign the public key in question to the PublicKey field of
the Request. For case 2, leave the PublicKey field empty and assign the private
key to the PrivateKey field of the Request, and the public key will be
automatically extracted and the appropriate signature generated. For case 3,
leave both the PublicKey and PrivateKey fields empty and assign the PKCS#10
certificate signed request to the CSR field. Note that when providing a PKCS#10
certificate signing request, none of the fields in the CSR are examined by HVCA
except for the public key and the signature, and none of the fields in the CSR
are automatically copied to the Request object.

#### func (Request) Equal

```go
func (r Request) Equal(other Request) bool
```
Equal checks if two certificate requests are equivalent.

#### func (Request) MarshalJSON

```go
func (r Request) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a certificate request.

#### func (*Request) PKCS10

```go
func (r *Request) PKCS10() (*x509.CertificateRequest, error)
```
PKCS10 converts a Request object into a PKCS#10 certificate signing request.

BUG(paul): Not all fields are currently marshalled into the PKCS#10 request. The
fields currently marshalled include: subject distinguished name (all fields,
including extra attributes); subject alternative names (excluding other names);
and extended key usages.

#### func (*Request) UnmarshalJSON

```go
func (r *Request) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded certificate request and stores the result in
the object.

#### type SAN

```go
type SAN struct {
	DNSNames    []string
	Emails      []string
	IPAddresses []net.IP
	URIs        []*url.URL
	OtherNames  []OIDAndString
}
```

SAN is a list of Subject Alternative Name attributes to include in a
certificate. See RFC 5280 #4.2.1.6.

#### func (*SAN) Equal

```go
func (s *SAN) Equal(other *SAN) bool
```
Equal checks if two subject alternative names lists are equivalent.

#### func (*SAN) MarshalJSON

```go
func (s *SAN) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a subject alternative names list.

#### func (*SAN) UnmarshalJSON

```go
func (s *SAN) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded subject alternative names list and stores
the result in the object.

#### type SANPolicy

```go
type SANPolicy struct {
	DNSNames    *ListPolicy
	Emails      *ListPolicy
	IPAddresses *ListPolicy
	URIs        *ListPolicy
	OtherNames  []TypeAndValuePolicy
}
```

SANPolicy is the subject alternative names field in a validation policy.

#### func (SANPolicy) MarshalJSON

```go
func (p SANPolicy) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a subject alternative names policy.

#### func (*SANPolicy) UnmarshalJSON

```go
func (p *SANPolicy) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded subject alternative names policy and stores
the result in the object.

#### type Semantics

```go
type Semantics struct {
	OID             asn1.ObjectIdentifier
	NameAuthorities []string
}
```

Semantics is the OID and optional name authorities for a qualified certificate
statement. See RFC 3739 #3.2.6.1.

#### func (Semantics) Equal

```go
func (s Semantics) Equal(other Semantics) bool
```
Equal checks if two semantics objects are equivalent.

#### func (Semantics) MarshalJSON

```go
func (s Semantics) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a semantics object.

#### func (*Semantics) UnmarshalJSON

```go
func (s *Semantics) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded semantics object and stores the result in
the object.

#### type SemanticsPolicy

```go
type SemanticsPolicy struct {
	Identifier      *StringPolicy `json:"identifier"`
	NameAuthorities *ListPolicy   `json:"name_authorities"`
}
```

SemanticsPolicy is the semantics field in the qualified statements field in a
validation policy.

#### type StringPolicy

```go
type StringPolicy struct {
	Presence Presence `json:"presence"`
	Format   string   `json:"format"`
}
```

StringPolicy is a string value entry in a validation policy.

#### type SubjectDAPolicy

```go
type SubjectDAPolicy struct {
	Gender               *StringPolicy        `json:"gender,omitempty"`
	DateOfBirth          Presence             `json:"date_of_birth,omitempty"`
	PlaceOfBirth         *StringPolicy        `json:"place_of_birth,omitempty"`
	CountryOfCitizenship *ListPolicy          `json:"country_of_citizenship,omitempty"`
	CountryOfResidence   *ListPolicy          `json:"country_of_residence,omitempty"`
	ExtraAttributes      []TypeAndValuePolicy `json:"extra_attributes,omitempty"`
}
```

SubjectDAPolicy is the subject directory attributes field in a validation
policy.

#### func (SubjectDAPolicy) MarshalJSON

```go
func (p SubjectDAPolicy) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a subject directory attributes policy.

#### func (*SubjectDAPolicy) UnmarshalJSON

```go
func (p *SubjectDAPolicy) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded subject directory attributes names policy
and stores the result in the object.

#### type SubjectDNPolicy

```go
type SubjectDNPolicy struct {
	CommonName         *StringPolicy
	Organization       *StringPolicy
	OrganizationalUnit *ListPolicy
	Country            *StringPolicy
	State              *StringPolicy
	Locality           *StringPolicy
	StreetAddress      *StringPolicy
	Email              *StringPolicy
	JOILocality        *StringPolicy
	JOIState           *StringPolicy
	JOICountry         *StringPolicy
	BusinessCategory   *StringPolicy
	ExtraAttributes    []TypeAndValuePolicy
}
```

SubjectDNPolicy is a subject distinguished name field in a validation policy.

#### func (SubjectDNPolicy) MarshalJSON

```go
func (p SubjectDNPolicy) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a subject distinguished name policy.

#### func (*SubjectDNPolicy) UnmarshalJSON

```go
func (p *SubjectDNPolicy) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded subject distinguished name policy and stores
the result in the object.

#### type TypeAndValuePolicy

```go
type TypeAndValuePolicy struct {
	OID         asn1.ObjectIdentifier `json:"-"`
	Static      bool                  `json:"static"`
	ValueType   ValueType             `json:"value_type"`
	ValueFormat string                `json:"value_format"`
	MinCount    int64                 `json:"mincount"`
	MaxCount    int64                 `json:"maxcount"`
}
```

TypeAndValuePolicy is a type and value entry in a validation policy.

#### type Validity

```go
type Validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}
```

Validity contains the requested not-before and not-after times for a
certificate. If NotAfter is set to time.Unix(0, 0), the maximum duration allowed
by the validation policy will be applied.

#### func (*Validity) Equal

```go
func (v *Validity) Equal(other *Validity) bool
```
Equal checks if two validity objects are equivalent.

#### func (*Validity) MarshalJSON

```go
func (v *Validity) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a validity object.

#### func (*Validity) UnmarshalJSON

```go
func (v *Validity) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded validity object and stores the result in the
object.

#### type ValidityPolicy

```go
type ValidityPolicy struct {
	SecondsMin            int64 `json:"secondsmin"`
	SecondsMax            int64 `json:"secondsmax"`
	NotBeforeNegativeSkew int64 `json:"not_before_negative_skew"`
	NotBeforePositiveSkew int64 `json:"not_before_positive_skew"`
}
```

ValidityPolicy is a validity field in a validation policy.

#### type ValueType

```go
type ValueType int
```

ValueType is a value_type field in a validation policy.

```go
const (
	IA5String ValueType = iota + 1
	PrintableString
	UTF8String
	Integer
	DER
	Nil
)
```
ValueType value constants.

#### func (ValueType) MarshalJSON

```go
func (v ValueType) MarshalJSON() ([]byte, error)
```
MarshalJSON returns the JSON encoding of a value type value.

#### func (ValueType) String

```go
func (v ValueType) String() string
```
String returns a description of the value type value.

#### func (*ValueType) UnmarshalJSON

```go
func (v *ValueType) UnmarshalJSON(b []byte) error
```
UnmarshalJSON parses a JSON-encoded value type value and stores the result in
the object.
