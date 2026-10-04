package main

import (
	"context"
	"fmt"
	"os"

	"github.com/sacloud/sacloud-sdk-go/api/kms"
	v1 "github.com/sacloud/sacloud-sdk-go/api/kms/apis/v1"
	"github.com/sacloud/sacloud-sdk-go/common/saclient"
)

type sakuraKMS struct {
	keys kms.KeyAPI
}

// Credentials are left to saclient, not read here: API keys and service
// principals then resolve the way the SDK documents them.
func newSakuraKMS() (*sakuraKMS, error) {
	var sc saclient.Client
	if err := sc.SetEnviron(os.Environ()); err != nil {
		return nil, fmt.Errorf("configure saclient: %w", err)
	}
	if err := sc.Populate(); err != nil {
		return nil, fmt.Errorf("configure saclient: %w", err)
	}
	client, err := kms.NewClient(&sc)
	if err != nil {
		return nil, err
	}
	return &sakuraKMS{keys: kms.NewKeyOp(client)}, nil
}

func (k *sakuraKMS) Encrypt(ctx context.Context, keyID string, plaintext []byte) (string, error) {
	return k.keys.Encrypt(ctx, keyID, plaintext, v1.EncryptionRequestAlgoAes256Gcm)
}

func (k *sakuraKMS) Decrypt(ctx context.Context, keyID, ciphertext string) ([]byte, error) {
	return k.keys.Decrypt(ctx, keyID, ciphertext)
}
