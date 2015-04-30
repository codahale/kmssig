package kmssig_test

import (
	"github.com/awslabs/aws-sdk-go/service/kms"
	"github.com/codahale/kmssig"
)

type FakeKMS struct {
	EncryptInputs  []kms.EncryptInput
	EncryptOutputs []kms.EncryptOutput

	DecryptInputs  []kms.DecryptInput
	DecryptOutputs []kms.DecryptOutput
	DecryptErrors  []error
}

func (f *FakeKMS) Encrypt(req *kms.EncryptInput) (*kms.EncryptOutput, error) {
	f.EncryptInputs = append(f.EncryptInputs, *req)
	resp := f.EncryptOutputs[0]
	f.EncryptOutputs = f.EncryptOutputs[1:]
	return &resp, nil
}

func (f *FakeKMS) Decrypt(req *kms.DecryptInput) (*kms.DecryptOutput, error) {
	f.DecryptInputs = append(f.DecryptInputs, *req)
	if f.DecryptErrors != nil {
		err := f.DecryptErrors[0]
		f.DecryptErrors = f.DecryptErrors[1:]
		return nil, err
	}
	resp := f.DecryptOutputs[0]
	f.DecryptOutputs = f.DecryptOutputs[1:]
	return &resp, nil
}

var _ kmssig.KeyManagement = &FakeKMS{}
