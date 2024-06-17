package util

import(
	"errors"
	"encoding/pem"
	"crypto/rsa"
    "crypto/x509"
	"encoding/base64"

	"github.com/rs/zerolog/log"
)

var childLogger = log.With().Str("internal", "util").Logger()

func ParsePEMToPrivateKey(pemString string) (*rsa.PrivateKey, error) {
    childLogger.Debug().Msg("ParsePEMToPrivateKey")

	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, errors.New("Failed to decode PEM-encoded key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return nil, err
    }

	return privateKey, nil
}

func ParsePemToCertx509(pemString string) (*x509.Certificate, error) {
    childLogger.Debug().Msg("ParsePemToCertx509")

	block, _ := pem.Decode([]byte(pemString))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("Failed to decode PEM-encoded cert")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return nil, err
    }

	return cert, nil
}

func DecodeB64(base64String string) (string, error){
    childLogger.Debug().Msg("DecodeB64")

    decodedBytes, err := base64.StdEncoding.DecodeString(base64String)
    if err != nil {
		return "", err
    }

	decodedString := string(decodedBytes)

	return decodedString, nil
}