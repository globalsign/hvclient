// +build integration

/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package hvclient_test

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/globalsign/hvclient"
	"github.com/globalsign/hvclient/internal/testhelpers"
)

func TestMain(m *testing.M) {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	if testClient, err = hvclient.NewClientFromFile(ctx, testLoginConfigFilename); err != nil {
		log.Fatalf("couldn't create HVCA client: %v", err)
	}

	os.Exit(m.Run())
}

// Counters and stats values.
const (
	testCounterCertsIssuedMinimum  = 4
	testCounterCertsRevokedMinimum = 1
	testQuotaIssuanceMaximum       = 999995
	testStatsExpiringTotalCount    = 1
	testStatsInvalidPageSize       = 200
	testStatsIssuedTotalCount      = 4
	testStatsMaximumPageSize       = 100
	testStatsRevokedTotalCount     = 1
)

// Certificate values.
const (
	testRetrieveBadCertificateSerialNumber          = "not_even_a_number"
	testRetrieveCertificateSerialNumber             = "01BE04ABA4D398ABA21D3C6E56274D18"
	testRetrieveInvalidCertificateSerialNumber      = "1"
	testRetrieveNonexistentCertificateSerialNumber  = "01010101010101010101010101010101"
	testRevokeCertificateSerialNumberAlreadyRevoked = "01CFABDF1EBA6325930BF8B6FFD89F12"
)

// Claims values.
const (
	testClaimAlreadyClaimedDomain  = "no.such.domain.com"
	testClaimAlreadyDeletedID      = "01586EEC5B5C4E8F8B2D906C11E2F7B2"
	testClaimBadID                 = "not_even_an_id"
	testClaimInvalidDomain         = "11111111"
	testClaimNonexistentID         = "01010101010101010101010101010101"
	testClaimPendingID             = "016B3BA9F4A57A2D4785D9EC5FD8EA89"
	testClaimSubmitAndDeleteDomain = "domain.submit.and.delete.org"
)

// Config file names.
var (
	testLoginConfigFilename             = testhelpers.MustGetConfigFromEnv("HVCLIENT_TEST_CONFIG_PKCS8")
	testP10ConfigFilename               = testhelpers.MustGetConfigFromEnv("HVCLIENT_TEST_CONFIG_PKCS10")
	testLoginEncryptedConfigFilename    = testhelpers.MustGetConfigFromEnv("HVCLIENT_TEST_CONFIG_ENCRYPTED_KEY")
	testBadKeySecretLoginConfigFilename = testhelpers.MustGetConfigFromEnv("HVCLIENT_TEST_CONFIG_BAD_API_CREDS")
)

// Other values.
var (
	testClient            *hvclient.Client
	testTimeout           = time.Second * 5
	timeoutErrorSubstring = "context deadline exceeded"
)

// Expected API errors.
var (
	testAPIErrorBadRequest = hvclient.APIError{
		StatusCode:  400,
		Description: "Invalid certificate issuance request",
	}
	testAPIErrorUnauthorized = hvclient.APIError{
		StatusCode:  401,
		Description: "Unauthorized",
	}
	testAPIErrorNotFound = hvclient.APIError{
		StatusCode:  404,
		Description: "Not Found",
	}
	testAPIErrorExistingDomain = hvclient.APIError{
		StatusCode:  409,
		Description: `Claim for domain "no.such.domain.com." already exists`,
	}
	testAPIErrorInvalidPage = hvclient.APIError{
		StatusCode:  422,
		Description: "page: invalid value",
	}
	testAPIErrorInvalidPageSize = hvclient.APIError{
		StatusCode:  422,
		Description: "per_page: must be between 1 and 100",
	}
	testAPIErrorWindowTooLong = hvclient.APIError{
		StatusCode:  422,
		Description: "to: time window exceeding max of 30 days",
	}
	testAPIErrorInvalidIDLength = hvclient.APIError{
		StatusCode:  422,
		Description: "invalid ID length",
	}
	testAPIErrorInvalidSerialNumberFormat = hvclient.APIError{
		StatusCode:  422,
		Description: "invalid serial number format",
	}
	testAPIErrorInvalidDomain = hvclient.APIError{
		StatusCode:  422,
		Description: "domain name needs at least one dot",
	}
	testAPIErrorInvalidKey = hvclient.APIError{
		StatusCode:  422,
		Description: "public_key: invalid encoding",
	}
	testAPIErrorUnsupportedKeyType = hvclient.APIError{
		StatusCode:  422,
		Description: "public_key: unsupported key type: RSA",
	}
	testAPIErrorAgainstPolicy = hvclient.APIError{
		StatusCode:  422,
		Description: "subject_dn.email: is forbidden",
	}
)

// CertInfo expected results.
var testRetrieveCertificateCertInfo = hvclient.CertInfo{
	PEM: "-----BEGIN CERTIFICATE-----\n" +
		"MIIEaDCCA1CgAwIBAgIQAb4Eq6TTmKuiHTxuVidNGDANBgkqhkiG9w0BAQsFADBS\n" +
		"MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEoMCYGA1UE\n" +
		"AxMfR2xvYmFsU2lnbiBOb24tUHVibGljIEhWQ0EgRGVtbzAeFw0xODEwMDUxNDE4\n" +
		"MzNaFw0xOTAxMDMxMjM4MzNaMDcxHzAdBgNVBAoMFkdsb2JhbFNpZ24gRW5naW5l\n" +
		"ZXJpbmcxFDASBgNVBAMMC0xlaWZFcmlrc29uMIIBIjANBgkqhkiG9w0BAQEFAAOC\n" +
		"AQ8AMIIBCgKCAQEAoyM0UV/nTOiSVF2RIGaBbc7CcsUuEoXb3p1EyK/86IGAeUQ2\n" +
		"BHznS2qIg90YQfO06AXpGtR5s/nPJI7nO00yg0T27ccsfGQkegmZ52Wi2qgmy1Gz\n" +
		"wC7PQlxHZ91OVnEVFxMnU5FtUsAXSZN2M7cRMas+bnZs0a3wdoDg4Xguh0tldN+d\n" +
		"Yfqk8JDMj085t/F9Ga2d23EuSSLjWU55q97s7ATzhM0GRwCOxxHfOZFnBFLmokbC\n" +
		"NwIhSTMO06NAlxjJ0zsbRT6fYHySqIk30hQ3rldbKOLDi2BD9baDvbNb63Fpe2iA\n" +
		"Fu+l+Al3MPJurcjg8ToUAZLw0d34/Bj3hN06dwIDAQABo4IBUzCCAU8wEwYDVR0l\n" +
		"BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFGQx5YtVKQAHvU50aowF0lhIwopwMEQG\n" +
		"A1UdHwQ9MDswOaA3oDWGM2h0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3Nu\n" +
		"cGh2Y2FkZW1vc2hhMmczLmNybDAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFGdLB+kJ\n" +
		"8fF7Msy9hRxOJw3OocxsMA4GA1UdDwEB/wQEAwIDqDCBlgYIKwYBBQUHAQEEgYkw\n" +
		"gYYwPAYIKwYBBQUHMAGGMGh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2NhL2dz\n" +
		"bnBodmNhZGVtb3NoYTJnMzBGBggrBgEFBQcwAoY6aHR0cDovL3NlY3VyZS5nbG9i\n" +
		"YWxzaWduLmNvbS9jYWNlcnQvZ3NucGh2Y2FkZW1vc2hhMmczLmNydDANBgkqhkiG\n" +
		"9w0BAQsFAAOCAQEAR/hUSJZGyc0XcpyF1jZ8pLnzdIqEfVxNa4LYdzsWBJIPCV/X\n" +
		"XFb4g7WlCjrBk7P2hHy5NQ/GAvyyzbF+s4ot/V38tMkZ9ZMbKqwV2+U0jGDEm96z\n" +
		"ru1+6ocBpef4GCOueWxKNoW5cWOi1Ka66HAP1ZW1dXk5CkAn6r2ND/5WVglaigWy\n" +
		"OiUdIVHAC0vn6L2Q/pCEVTxcna3EMXP4Je0NQeCCJ7QA7LCoJWTCSjv6FlJFYB78\n" +
		"KNuaGdsd+wHmibvRCcTd2cVFk8NVF07Shnb4ubsjEQ2jdyQrmi4AfDIw4SlFA5Vu\n" +
		"a6dOVc/7SWfuoMcERo4GKNpMd6BAn8wpmM+B5A==\n" +
		"-----END CERTIFICATE-----\n" +
		"",
	Status:    hvclient.StatusIssued,
	UpdatedAt: time.Unix(1538749074, 0),
}

// Stats expected results.
var (
	testStatsTooLongFrom = time.Unix(1, 0)
	testStatsTooLongTo   = time.Unix(10000000, 0)
	testStatsIssuedFrom  = time.Unix(1538748600, 0)
	testStatsIssuedTo    = time.Unix(1538749400, 0)
	testStatsIssuedMetas = []hvclient.CertMeta{
		{
			SerialNumber: "01CFABDF1EBA6325930BF8B6FFD89F12",
			NotBefore:    time.Unix(1538748659, 0),
			NotAfter:     time.Unix(1546518659, 0),
		},
		{
			SerialNumber: "01F61750041A52E5561F0DC342A4BF3D",
			NotBefore:    time.Unix(1538748944, 0),
			NotAfter:     time.Unix(1546518944, 0),
		},
		{
			SerialNumber: "01BE04ABA4D398ABA21D3C6E56274D18",
			NotBefore:    time.Unix(1538749113, 0),
			NotAfter:     time.Unix(1546519113, 0),
		},
		{
			SerialNumber: "0120706646DB29EDC8F168F76ACE65C1",
			NotBefore:    time.Unix(1538749287, 0),
			NotAfter:     time.Unix(1546519287, 0),
		},
	}

	testStatsRevokedFrom  = time.Unix(1538750600, 0)
	testStatsRevokedTo    = time.Unix(1538750700, 0)
	testStatsRevokedMetas = []hvclient.CertMeta{
		{
			SerialNumber: "01CFABDF1EBA6325930BF8B6FFD89F12",
			NotBefore:    time.Unix(1538748659, 0),
			NotAfter:     time.Unix(1546518659, 0),
		},
	}

	testStatsExpiringFrom  = time.Unix(1546518844, 0)
	testStatsExpiringTo    = time.Unix(1546519044, 0)
	testStatsExpiringMetas = []hvclient.CertMeta{
		{
			SerialNumber: "01F61750041A52E5561F0DC342A4BF3D",
			NotBefore:    time.Unix(1538748944, 0),
			NotAfter:     time.Unix(1546518944, 0),
		},
	}
)

// Expected trust chain certificates.
var testTrustChainCerts = []string{
	`-----BEGIN CERTIFICATE-----
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
`,
}
