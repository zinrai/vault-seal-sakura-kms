package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	transitseal "github.com/hashicorp/go-kms-wrapping/wrappers/transit/v2"
)

type reversingKMS struct{}

func (reversingKMS) Encrypt(_ context.Context, _ string, plaintext []byte) (string, error) {
	b := slices.Clone(plaintext)
	slices.Reverse(b)
	return base64.StdEncoding.EncodeToString(b), nil
}

func (reversingKMS) Decrypt(_ context.Context, _ string, ciphertext string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, errors.New("not ours")
	}
	slices.Reverse(b)
	return b, nil
}

func TestVaultsTransitSealRoundTripsThroughTheSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "kms.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: transitHandler(reversingKMS{}, "113801674133")}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })

	seal := transitseal.NewWrapper()
	if _, err := seal.SetConfig(t.Context(), wrapping.WithConfigMap(map[string]string{
		"address":         "unix://" + socket,
		"mount_path":      "transit/",
		"key_name":        "113801674133",
		"disable_renewal": "true",
	})); err != nil {
		t.Fatal(err)
	}

	rootKey := []byte("the root key that unseals Vault")
	blob, err := seal.Encrypt(t.Context(), rootKey)
	if err != nil {
		t.Fatalf("the seal cannot encrypt: %v", err)
	}
	got, err := seal.Decrypt(t.Context(), blob)
	if err != nil {
		t.Fatalf("the seal cannot decrypt what it encrypted: %v", err)
	}
	if !bytes.Equal(got, rootKey) {
		t.Errorf("decrypted %q, want %q", got, rootKey)
	}
}
