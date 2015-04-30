// Package kmssig provides functionality for signing and verifying files using
// AWS's Key Management Service.
package kmssig

import (
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"io"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/service/kms"
)

var (
	// ErrInvalidSignature is returned when the signature for the given data is
	// invalid.
	ErrInvalidSignature = errors.New("signature is invalid")
)

type KeyManagement interface {
	Encrypt(*kms.EncryptInput) (*kms.EncryptOutput, error)
	Decrypt(*kms.DecryptInput) (*kms.DecryptOutput, error)
}

// Sign creates a signature for the given data.
//
// It first hashes the data using SHA-512, then encrypts that hash using the
// given KMS client. The resulting ciphertext is the signature. If any bit of
// either the data, the context, or the signature are changed, the signature
// will be invalid.
func Sign(keys KeyManagement, keyID string, ctxt map[string]string, r io.Reader) ([]byte, error) {
	h := sha512.New()
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}
	digest := h.Sum(nil)

	resp, err := keys.Encrypt(&kms.EncryptInput{
		EncryptionContext: context(ctxt),
		KeyID:             aws.String(keyID),
		Plaintext:         digest,
	})
	if err != nil {
		return nil, err
	}

	return resp.CiphertextBlob, nil
}

// Verify verifies a signature for the given data.
//
// It first hashes the data using SHA-512 then decrypts the signature using the
// given KMS client. The resulting plaintext is compared in constant time to the
// SHA-512 hash. If any bit of either the data, the context, or the signature
// are changed, Verify will return ErrInvalidSignature. If the signature is
// valid, Verify will return the key ID the signature was created with.
func Verify(keys KeyManagement, ctxt map[string]string, r io.Reader, sig []byte) (string, error) {
	h := sha512.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	digest := h.Sum(nil)

	resp, err := keys.Decrypt(&kms.DecryptInput{
		EncryptionContext: context(ctxt),
		CiphertextBlob:    sig,
	})
	if err != nil {
		if e, ok := err.(aws.APIError); ok &&
			e.Code == "InvalidCiphertextException" {
			return "", ErrInvalidSignature
		}
		return "", err
	}

	if !hmac.Equal(resp.Plaintext, digest) {
		return "", ErrInvalidSignature
	}

	return *resp.KeyID, nil
}

func context(ctxt map[string]string) *map[string]*string {
	m := make(map[string]*string, len(ctxt))
	for k, v := range ctxt {
		m[k] = aws.String(v)
	}
	return &m
}
