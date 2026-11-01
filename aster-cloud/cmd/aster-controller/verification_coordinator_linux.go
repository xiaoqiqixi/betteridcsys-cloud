//go:build linux

package main

import (
	"aster/cloud/internal/controllerbackup"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Private root-manager protocol, not a shortcut around installation approval.
// FD 3 is an anonymous root-parent socket. Only the operation/nonce, freshly
// rederived public proof and approved dedicated UID/GID cross it. Credentials,
// paths and executable selectors are deliberately absent from this protocol.
func verificationCoordinator() error {
	peer, err := unix.GetsockoptUcred(3, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if os.Getuid() != 0 || os.Geteuid() != 0 || err != nil || peer.Uid != 0 || peer.Pid <= 1 || int(peer.Pid) != os.Getppid() {
		return controllerbackup.ErrInvalid
	}
	for _, address := range []func(int) (unix.Sockaddr, error){unix.Getsockname, unix.Getpeername} {
		value, err := address(3)
		endpoint, ok := value.(*unix.SockaddrUnix)
		if err != nil || !ok || endpoint.Name != "" {
			return controllerbackup.ErrInvalid
		}
	}
	file := os.NewFile(3, "verification-manager")
	connection, err := net.FileConn(file)
	file.Close()
	if err != nil {
		return controllerbackup.ErrInvalid
	}
	defer connection.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := connection.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return controllerbackup.ErrInvalid
	}
	reader := bufio.NewReaderSize(connection, 4097)
	read := func() ([]byte, error) {
		raw, err := reader.ReadSlice('\n')
		if err != nil || len(raw) > 4096 {
			return nil, controllerbackup.ErrInvalid
		}
		return append([]byte(nil), raw...), nil
	}
	canonical := func(raw []byte, value any) bool {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(value) != nil {
			return false
		}
		encoded, err := json.Marshal(value)
		return err == nil && bytes.Equal(raw, append(encoded, '\n'))
	}
	var request struct {
		Schema      int    `json:"schema"`
		OperationID string `json:"operation_id"`
		Nonce       string `json:"nonce"`
	}
	raw, err := read()
	if err != nil || !canonical(raw, &request) || request.Schema != 1 || len(request.Nonce) != 64 {
		return controllerbackup.ErrInvalid
	}
	if nonce, err := hex.DecodeString(request.Nonce); err != nil || len(nonce) != 32 || hex.EncodeToString(nonce) != request.Nonce {
		return controllerbackup.ErrInvalid
	}
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		return controllerbackup.ErrInvalid
	}
	// Monitor EOF even while authenticating/decrypting the original archive.
	// A second record, extra byte, half-close or parent death cancels admission;
	// this socket can never extend the original absolute approval deadline.
	response := make(chan []byte, 1)
	go func() {
		defer cancel()
		raw, err := read()
		if err != nil {
			return
		}
		response <- raw
		var extra [1]byte
		_, _ = reader.Read(extra[:])
	}()
	var approvedDeadline time.Time
	err = controllerbackup.RunTargetVerification(ctx, request.OperationID, func(proof controllerbackup.TargetVerificationRuntimeReport) (controllerbackup.VerificationSystemIdentity, error) {
		fail := func() (controllerbackup.VerificationSystemIdentity, error) {
			return controllerbackup.VerificationSystemIdentity{}, controllerbackup.ErrInvalid
		}
		if ctx.Err() != nil || int(peer.Pid) != os.Getppid() {
			return fail()
		}
		packet, err := json.Marshal(struct {
			Schema int                                              `json:"schema"`
			Nonce  string                                           `json:"nonce"`
			Proof  controllerbackup.TargetVerificationRuntimeReport `json:"proof"`
		}{1, request.Nonce, proof})
		if err != nil || len(packet) > 256<<10 {
			return fail()
		}
		packet = append(packet, '\n')
		sum := sha256.Sum256(packet)
		if connection.SetDeadline(time.Now().Add(90*time.Second)) != nil {
			return fail()
		}
		if n, err := connection.Write(packet); err != nil || n != len(packet) {
			return fail()
		}
		var raw []byte
		select {
		case <-ctx.Done():
			return fail()
		case raw = <-response:
		}
		var approved struct {
			Schema      int    `json:"schema"`
			Nonce       string `json:"nonce"`
			ProofSHA256 string `json:"proof_sha256"`
			UID         uint32 `json:"uid"`
			GID         uint32 `json:"gid"`
		}
		if !canonical(raw, &approved) || approved.Schema != 1 || approved.Nonce != request.Nonce || approved.ProofSHA256 != hex.EncodeToString(sum[:]) ||
			ctx.Err() != nil || int(peer.Pid) != os.Getppid() || connection.SetDeadline(time.Time{}) != nil {
			return fail()
		}
		approvedDeadline, err = time.Parse(time.RFC3339Nano, proof.Phase.ExpiresAt)
		if err != nil {
			return fail()
		}
		return controllerbackup.VerificationSystemIdentity{UID: approved.UID, GID: approved.GID}, nil
	})
	// The service waits for real child exit before returning cancellation.
	// This means only that the coordinator stopped, never that migration passed.
	if errors.Is(err, context.Canceled) && ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) && !approvedDeadline.IsZero() && !time.Now().Before(approvedDeadline) {
		return nil
	}
	return err
}
