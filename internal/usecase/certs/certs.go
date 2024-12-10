package certs

import(
	"context"
	"encoding/pem"
	"crypto/x509"

	"github.com/rs/zerolog/log"

	"github.com/lambda-go-auth-apigw/internal/erro"
	"github.com/lambda-go-auth-apigw/pkg/observability"
)

var childLogger = log.With().Str("useCase", "certs").Logger()

type UseCaseCerts struct{
	crl_pem	*[]byte
}

func NewUseCaseCerts(crl_pem *[]byte) *UseCaseCerts{
	childLogger.Debug().Msg("NewUseCase")

	return &UseCaseCerts{
		crl_pem: crl_pem,
	}
}

func(u *UseCaseCerts) VerifyCertCRL(ctx context.Context, 
									certX509PemDecoded string) (bool, error){
	childLogger.Debug().Msg("VerifyCertCRL")

	span := observability.Span(ctx, "useCase.VerifyCertCRL")	
    defer span.End()

	// The cert must be informed
	if certX509PemDecoded == ""{
		log.Error().Msg("Client Cert no Informed !!!")
		return false, erro.ErrCertRevoked
	}

	certX509, err := ParsePemToCertx509(certX509PemDecoded)
	if err != nil {
		log.Debug().Msg("Erro ParsePemToCertx509 !!!")
		return false, erro.ErrParseCert
	}

	certSerialNumber := certX509.SerialNumber

	crl_list, err := x509.ParseRevocationList(*u.crl_pem)
	if err != nil {
		log.Error().Msg("Erro ParseRevocationList !!!")
		return false, err
	}

	for _, revokedCert := range crl_list.RevokedCertificateEntries {
		if revokedCert.SerialNumber.Cmp(certSerialNumber) == 0 {
			return true, nil
		}
	}

	return false, nil
}

func ParsePemToCertx509(pemString string) (*x509.Certificate, error) {
    childLogger.Debug().Msg("ParsePemToCertx509")

	block, _ := pem.Decode([]byte(pemString))
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