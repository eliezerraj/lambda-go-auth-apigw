package util

/*
	import(
		"os"
		"crypto/x509"
		"encoding/pem"
		"crypto/rsa"
	
		"github.com/rs/zerolog/log"

		"github.com/lambda-go-authorizer-cert/internal/erro"
		"github.com/lambda-go-authorizer-cert/internal/model"
	)

func LoadRSAKey() (*model.RSA_Key){
	log.Debug().Msg("LoadRSAKey")

	var keys model.RSA_Key

	if os.Getenv("SECRET_NAME_H256") !=  "" {
		keys.SecretNameH256 = os.Getenv("SECRET_NAME_H256")
	}

	// Load Private key
	private_key, err := os.ReadFile("../cmd/vault/private_key.pem")
	if err != nil {
		log.Error().Err(err).Msg("erro ReadFile - private_key")
		return nil
	}

	keys.RSAPrivateKeyByte = private_key

	block, _ := pem.Decode(private_key)
	if block == nil || block.Type != "PRIVATE KEY" {
		log.Error().Err(erro.ErrDecodeKey).Msg("erro Decode")
		return nil
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Error().Err(err).Msg("erro ParsePKCS8PrivateKey")
		return nil
	}

	keys.PrivateKeyPem = privateKey.(*rsa.PrivateKey)

	return &keys
}*/