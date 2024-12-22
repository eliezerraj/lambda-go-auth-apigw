package certs

import(
	"fmt"
	"context"
	"encoding/pem"
	"crypto/x509"
	"encoding/base64"

	"github.com/rs/zerolog/log"

	"github.com/lambda-go-auth-apigw/internal/erro"
	"github.com/lambda-go-auth-apigw/pkg/observability"
)

var childLogger = log.With().Str("useCase", "certs").Logger()

type UseCaseCerts struct{
	crl_pem	*string
}

func NewUseCaseCerts(crl_pem *string) *UseCaseCerts{
	childLogger.Debug().Msg("NewUseCase")

	return &UseCaseCerts{
		crl_pem: crl_pem,
	}
}

func(u *UseCaseCerts) VerifyCertCRL(ctx context.Context, 
									certX509PemEncoded string) (bool, error){
	childLogger.Debug().Msg("VerifyCertCRL")

	span := observability.Span(ctx, "useCase.VerifyCertCRL")	
    defer span.End()

	// The cert must be informed
	if certX509PemEncoded == ""{
		log.Error().Msg("Client Cert no Informed !!!")
		return false, erro.ErrCertRevoked
	}

	certX509PemDecoded, err := base64.StdEncoding.DecodeString(certX509PemEncoded)
	if err != nil {
		return false, err
	}
	certX509PemDecoded_str := string(certX509PemDecoded)
	certX509, err := ParsePemToCertx509(&certX509PemDecoded_str)
	if err != nil {
		childLogger.Error().Err(err).Msg("Erro ParsePemToCertx509 !!!")
		return false, erro.ErrParseCert
	}

	certSerialNumber := certX509.SerialNumber

	childLogger.Debug().Interface("= 1 > certSerialNumber : ", certSerialNumber).Msg("")
	childLogger.Debug().Interface("= 1 > crl_pem : ", *u.crl_pem).Msg("")

	block, _ := pem.Decode([]byte(*u.crl_pem))
	if block == nil || block.Type != "X509 CRL" {
		childLogger.Error().Err(err).Msg("erro decode crl")
		return false, err
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		childLogger.Error().Err(err).Msg("erro ParseRevocationList crl")
		return false, err
	}

	fmt.Printf("Issuer: %s\n", crl.Issuer)
	fmt.Printf("ThisUpdate: %s\n", crl.ThisUpdate)
	fmt.Printf("NextUpdate: %s\n", crl.NextUpdate)
	fmt.Printf("Number of Revoked Cert: %d\n", len(crl.RevokedCertificates))

	// Iterate over revoked certificates
	for i, revokedCert := range crl.RevokedCertificateEntries {
		fmt.Printf("Revoked Certificate %d:\n", i+1)
		fmt.Printf("Serial Number: %s\n", revokedCert.SerialNumber)
		fmt.Printf("Revocation Time: %s\n", revokedCert.RevocationTime)
		if revokedCert.SerialNumber.Cmp(certSerialNumber) == 0 {
			return true, nil
		}
		return true, nil
	}

	return false, nil
}

func ParsePemToCertx509(pemString *string) (*x509.Certificate, error) {
    childLogger.Debug().Msg("ParsePemToCertx509")

	block, _ := pem.Decode([]byte(*pemString))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, erro.ErrDecodeCert
	}

	cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
		log.Error().Msg("Erro ParseCertificate !!!")
        return nil, err
    }

	return cert, nil
}