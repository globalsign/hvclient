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

import "flag"

const (
	flagNamePublicKey  = "publickey"
	flagNamePrivateKey = "privatekey"
	flagNameCSR        = "csr"
	flagNameTemplate   = "template"
)

// General flags.
var (
	fHelp    = flag.Bool("h", false, "show online help")
	fVersion = flag.Bool("v", false, "show version information")
)

// PKI flags.
var (
	fGenRSA  = flag.Int("genrsa", 0, "generate RSA private key of given bit size")
	fEncrypt = flag.Bool("encrypt", false, "encrypt generated private key")
)

// Certificate request flags.
var (
	fPublicKey      = flag.String(flagNamePublicKey, "", "path to public key")
	fPrivateKey     = flag.String(flagNamePrivateKey, "", "path to private key")
	fCSR            = flag.String(flagNameCSR, "", "path to PKCS#10 certificate signing request")
	fGenCSR         = flag.Bool("gencsr", false, "generate a PKCS#10 certificate signing request from a -privatekey")
	fTemplate       = flag.String(flagNameTemplate, "", "path to certificate request template file")
	fSampleTemplate = flag.Bool("sampletemplate", false, "output sample certificate request template file")
	fConfigFile     = flag.String("config", "", "path to configuration file (default: $HOME/.hvclient/hvclient.conf)")
	fGenerate       = flag.Bool("generate", false, "output request JSON without making request")
	fCSROut         = flag.Bool("csrout", false, "output PKCS#10 certificate signing request without making request")
)

// Validity flags.
var (
	fNotBefore = flag.String("notbefore", "", "certificate not-before time in layout "+defaultTimeLayout+" (default: current time)")
	fNotAfter  = flag.String("notafter", "", "certificate not-after time in layout "+defaultTimeLayout+" (default: maximum allowed by policy)")
	fDuration  = flag.String("duration", "", "requested certificate duration e.g. 60m, 24h, 30d (default: maximum allowed by policy)")
)

// Subject distinguished name flags.
var (
	fSubjectCommonName         = flag.String("commonname", "", "subject common name")
	fSubjectSerialNumber       = flag.String("serialnumber", "", "subject serial number (distinct from certificate serial number)")
	fSubjectOrganization       = flag.String("organization", "", "subject organization")
	fSubjectOrganizationalUnit = flag.String("organizationalunit", "", "comma-separated list of subject organizational unit(s)")
	fSubjectStreetAddress      = flag.String("streetaddress", "", "subject street address")
	fSubjectLocality           = flag.String("locality", "", "subject locality")
	fSubjectState              = flag.String("state", "", "subject state")
	fSubjectCountry            = flag.String("country", "", "subject country")
	fSubjectEmail              = flag.String("email", "", "subject email address (deprecated)")
	fSubjectJOILocality        = flag.String("joilocality", "", "subject jurisdiction locality")
	fSubjectJOIState           = flag.String("joistate", "", "subject jurisdiction state or province")
	fSubjectJOICountry         = flag.String("joicountry", "", "subject jurisdiction country")
	fSubjectBusinessCategory   = flag.String("businesscategory", "", "subject business category")
	fSubjectExtraAttributes    = flag.String("extraattributes", "", "subject extra attributes in format \"2.5.4.4=surname,2.5.4.5=serial_number")
)

// SAN values flags.
var (
	fDNSNames = flag.String("dnsnames", "", "comma-separated list of SAN DNS names")
	fEmails   = flag.String("emails", "", "comma-separated list of SAN email addresses")
	fIPs      = flag.String("ips", "", "comma-separated list of SAN IP addresses")
	fURIs     = flag.String("uris", "", "comma-separated list of SAN URIs")
)

// Other certificate request flags.

var fEKUs = flag.String("ekus", "", "extended key usages")

// Time window flags.
var (
	fFrom  = flag.String("from", "", "start of the time window in layout "+defaultTimeLayout+" (default: 30 days ago)")
	fTo    = flag.String("to", "", "end of the time window in layout "+defaultTimeLayout+" (default: current time)")
	fSince = flag.String("since", "", "duration of time window back from current time e.g. 60m, 24h, 30d")
)

// Pagination flags.
var (
	fPage       = flag.Int("page", 1, "page number for list-producing APIs")
	fPageSize   = flag.Int("pagesize", 100, "page size for list-producing APIs")
	fTotalCount = flag.Bool("totalcount", false, "show total count for list-producing APIs")
)

// Certificate flags.
var (
	fRetrieve = flag.String("retrieve", "", "retrieve the certificate with the specified serial number")
	fStatus   = flag.String("status", "", "show the status of the certificate with the specified serial number")
	fUpdated  = flag.String("updated", "", "show the updated-at time for the certificate with the specified serial number")
	fRevoke   = flag.String("revoke", "", "revoke the certificate with the specified serial number")
	fRekey    = flag.String("rekey", "", "rekey the certificate with the specified serial number")
)

// Account statistics and information flags.
var (
	fCountIssued   = flag.Bool("countissued", false, "show count of certificates issued")
	fCountRevoked  = flag.Bool("countrevoked", false, "show count of certificates revoked")
	fCertsIssued   = flag.Bool("certsissued", false, "list certificates issued during the time window")
	fCertsRevoked  = flag.Bool("certsrevoked", false, "list certificates revoked during the time window")
	fCertsExpiring = flag.Bool("certsexpiring", false, "list certificates expiring during the time window")
	fTrustChain    = flag.Bool("trustchain", false, "retrieve chain of trust for issued certificates")
	fQuota         = flag.Bool("quota", false, "show remaining quota of certificate issuances")
	fPolicy        = flag.Bool("policy", false, "retrieve validation policy")
)

// Domain claim flags.
var (
	fClaims         = flag.Bool("claims", false, "show pending or verified domain claims")
	fPending        = flag.Bool("pending", false, "use with -claims to show pending rather than verified domain claims")
	fClaimRetrieve  = flag.String("claimretrieve", "", "retrieve the domain claim with the specified ID")
	fClaimSubmit    = flag.String("claimsubmit", "", "submit a domain claim for the specified domain")
	fClaimDelete    = flag.String("claimdelete", "", "delete the domain claim with the specified ID")
	fClaimDNS       = flag.String("claimdns", "", "request assertion of domain control using DNS for the domain claim with the specified ID")
	fClaimHTTP      = flag.String("claimhttp", "", "request assertion of domain control using HTTP for the domain claim with the specified ID")
	fClaimEmail     = flag.String("claimemail", "", "request assertion of domain control using Email for the domain claim with the specified ID")
	fClaimEmailList = flag.String("claimemaillist", "", "request list of emails authorised to perform email validation for the domain claims with the specified ID")
	fEmailAddress   = flag.String("address", "", "email address used to send email to verify assertion of domain control using Email validation method for the domain claim")
	fScheme         = flag.String("scheme", "https", "protocol used to verify assertion of domain control using HTTP method for the domain claim")
	fAuthDomain     = flag.String("authdomain", "", "authorization domain name used to verify assertion of domain control for the domain claim")
	fClaimReassert  = flag.String("claimreassert", "", "reassert the domain claim with the specified ID")
)
