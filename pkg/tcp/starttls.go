package tcp

import (
	"bufio"
	"bytes"
	"fmt"

	"github.com/containous/traefik/v2/pkg/log"
)

var (
	postgresStartTLSMsg   = []byte{0, 0, 0, 8, 4, 210, 22, 47} //int32(8) + int32(80877103)
	postgresStartTLSReply = []byte{83}                         //S
)

// invokeStartTLSPostgresHandshake performs the postgres StartTLS
// handshake (client side). It sends the postgresStartTLSMsg
// and checkes if the server response matches the expected value.
// It returns an error on read/write failures on the connection
// or if the server response doesn't match.
func invokeStartTLSPostgresHandshake(conn WriteCloser) error {

	log.Debug("dreggn starttls handshake with target ")

	_, err := conn.Write(postgresStartTLSMsg)
	if err != nil {
		return err
	}

	b := make([]byte, 1)
	_, err = conn.Read(b)
	if err != nil {
		return err
	}

	if b[0] != postgresStartTLSReply[0] {
		return fmt.Errorf("unexpected postgres starttls response got %v want 'S' ", b)
	}
	return nil
}

// handleStartTLSHandshake performs a StartTLS Handshake (server side)
// It peeks some into some bytes of conn and
// tries to find out if the client performs a StartTLS handshake.
// If the client request does contain a StartTLS handshake signature
// the handshake is performed. After this step the client will
// start a TLS session.
// If no StartTLS signature is found the bytes of the connection
// are unmodified.
// In any case the caller must use the returned WriteCloser for
// further read/write operations.
// An error is retured if reading or writing to the WriteCloser fails.
//
// BEWARE: currently only postgres startTLS handshake flavor is currently implemented.
func handleStartTLSHandshake(conn WriteCloser) (WriteCloser, error) {

	startTLSConn := newStartTLSConn(conn)

	buf, err := startTLSConn.Peek(len(postgresStartTLSMsg))
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(buf, postgresStartTLSMsg) {
		log.Debug("doesn't seem to be postgres StartTLS handshake .. skipping")
		return startTLSConn, nil
	}

	//consume the bytes that we just peeked so far..
	startTLSConn.Read(buf)

	_, err = conn.Write(postgresStartTLSReply)
	if err != nil {
		return nil, err
	}

	log.Debug("dreggn part1 successful")

	return startTLSConn, nil
}

type startTLSConn struct {
	br *bufio.Reader
	WriteCloser
}

func newStartTLSConn(conn WriteCloser) startTLSConn {
	return startTLSConn{bufio.NewReader(conn), conn}
}

func (s startTLSConn) Peek(n int) ([]byte, error) {
	return s.br.Peek(n)
}

func (s startTLSConn) Read(p []byte) (int, error) {
	return s.br.Read(p)
}
