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

func imposeStartTLSPostgresClient(conn WriteCloser) error {

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

func imposeStartTLSPostgresServer(conn WriteCloser) (string, error) {

	startTLSConn := newStartTLSConn(conn)

	buf, err := startTLSConn.Peek(len(postgresStartTLSMsg))
	if err != nil {
		return "", err
	}

	if !bytes.Equal(buf, postgresStartTLSMsg) {
		log.Debug("doesn't seem to be postgres StartTLS handshake .. skipping")
		return startTLSConn.getPeeked(), nil
	}

	//consume the bytes that we just peeked so far..
	startTLSConn.Read(buf)

	_, err = conn.Write(postgresStartTLSReply)
	if err != nil {
		log.Fatal(err)
	}

	return startTLSConn.getPeeked(), nil
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

func (s startTLSConn) getPeeked() string {
	peeked, err := s.br.Peek(s.br.Buffered())
	if err != nil {
		log.Errorf("Could not get anything: %s", err)
		return ""
	}
	return string(peeked)
}
