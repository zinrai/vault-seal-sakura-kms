package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "vault-seal-sakura-kms: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	socket := flag.String("socket", "", "Unix socket to listen on (required)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()
	if *showVersion {
		printVersion()
		return nil
	}
	if *socket == "" {
		flag.Usage()
		return errors.New("-socket is required")
	}
	// From the environment only, not a flag: the key ID travels with the
	// credentials, so the KMS key is named in one place.
	keyID := os.Getenv("SAKURA_KMS_KEY_ID")
	if keyID == "" {
		return errors.New("SAKURA_KMS_KEY_ID is required")
	}

	k, err := newSakuraKMS()
	if err != nil {
		return err
	}
	l, err := listen(*socket)
	if err != nil {
		return err
	}
	slog.Info("serving", "socket", *socket, "key_id", keyID)
	return serve(l, transitHandler(k, keyID))
}

// A Unix socket, not TCP on loopback: on loopback any local process could
// ask the KMS to decrypt the seal key. Group-writable, not world: the vault
// service reaches it through its group.
func listen(socket string) (net.Listener, error) {
	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	l, err := net.Listen("unix", socket)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socket, 0o660); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func serve(l net.Listener, h http.Handler) error {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	if err := srv.Serve(l); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
