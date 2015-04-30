package kmssig_test

import (
	"bytes"
	"testing"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/service/kms"
	"github.com/codahale/kmssig"
)

func TestSign(t *testing.T) {
	ciphertext := []byte("this is some encrypted stuff")
	kms := &FakeKMS{
		EncryptOutputs: []kms.EncryptOutput{
			{
				CiphertextBlob: ciphertext,
			},
		},
	}
	ctxt := map[string]string{"A": "B"}
	data := []byte("this is definitely data")

	sig, err := kmssig.Sign(kms, "keyID", ctxt, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sig, ciphertext) {
		t.Errorf("Signature was %s, but expected %s", sig, ciphertext)
	}
}

func TestVerify(t *testing.T) {
	hash := []byte{
		0xf4, 0x82, 0x85, 0x3b, 0x2c, 0xf3, 0xc0, 0x26, 0x20, 0xed, 0x9d, 0x10,
		0xbf, 0xd6, 0x48, 0xb3, 0xb4, 0x6f, 0xb6, 0x39, 0x20, 0x08, 0xc8, 0xa1,
		0xde, 0x6c, 0x05, 0x3d, 0xa8, 0xd3, 0x55, 0x9e, 0xe3, 0xff, 0x2f, 0x13,
		0xeb, 0xd9, 0xd7, 0x44, 0xcf, 0x2a, 0xe0, 0x8f, 0x06, 0xdb, 0xff, 0x19,
		0x38, 0x81, 0x88, 0x64, 0x43, 0x22, 0x4d, 0x7b, 0x10, 0xb6, 0x39, 0xd0,
		0x00, 0x98, 0x11, 0x03,
	}
	sig := []byte("this is some encrypted stuff")
	kms := &FakeKMS{
		DecryptOutputs: []kms.DecryptOutput{
			{
				KeyID:     aws.String("keyID"),
				Plaintext: hash,
			},
		},
	}
	ctxt := map[string]string{"A": "B"}
	data := []byte("this is definitely data")

	keyID, err := kmssig.Verify(kms, ctxt, bytes.NewReader(data), sig)
	if err != nil {
		t.Fatal(err)
	}

	if v, want := keyID, "keyID"; v != want {
		t.Errorf("Key ID was %s but expected %s", v, want)
	}
}

func TestVerifyBadData(t *testing.T) {
	sig := []byte("this is some encrypted stuff")
	kms := &FakeKMS{
		DecryptErrors: []error{
			aws.APIError{
				StatusCode: 400,
				Code:       "InvalidCiphertextException",
			},
		},
	}
	ctxt := map[string]string{"A": "B"}
	data := []byte("this is definitely data")

	_, err := kmssig.Verify(kms, ctxt, bytes.NewReader(data), sig)
	if err != kmssig.ErrInvalidSignature {
		t.Errorf("Error was %v but expected %s", err, kmssig.ErrInvalidSignature)
	}
}

func TestVerifyBadSignature(t *testing.T) {
	hash := []byte("this is definitely not the right hash")
	sig := []byte("this is some encrypted stuff")
	kms := &FakeKMS{
		DecryptOutputs: []kms.DecryptOutput{
			{
				KeyID:     aws.String("keyID"),
				Plaintext: hash,
			},
		},
	}
	ctxt := map[string]string{"A": "B"}
	data := []byte("this is definitely data")

	_, err := kmssig.Verify(kms, ctxt, bytes.NewReader(data), sig)
	if err != kmssig.ErrInvalidSignature {
		t.Errorf("Error was %v but expected %s", err, kmssig.ErrInvalidSignature)
	}
}
