package tcp

import (
	"bytes"
	"fmt"
	"io"

	"github.com/containous/traefik/v2/pkg/log"
)

var (
	postgresStartTLSMsgLen = []byte{0, 0, 0, 8}     //8
	postgresStartTLSMsg    = []byte{4, 210, 22, 47} //80877103
	postgresStartTLSReply  = []byte{83}             //S
)

func imposeStartTLSPostgresClient(conn WriteCloser) error {

	_, err := conn.Write(postgresStartTLSMsgLen)
	if err != nil {
		return err
	}

	_, err = conn.Write(postgresStartTLSMsg)
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

func imposeStartTLSPostgresServer(conn WriteCloser) error {

	log.Debug("starting starttls")

	buf := make([]byte, 4)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(buf, postgresStartTLSMsgLen) {
		return fmt.Errorf("unexpected msg length in starttls handshake got: %v expected: %v", buf, postgresStartTLSMsgLen)
	}

	log.Debug("got %v", buf)

	_, err = io.ReadFull(conn, buf)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(buf, postgresStartTLSMsg) {
		return fmt.Errorf("unexpected data in starttls handshake got: %v", buf)
	}
	log.Debug("got %v", buf)

	_, err = conn.Write(postgresStartTLSReply)
	if err != nil {
		log.Fatal(err)
	}

	log.Debug("end starttls")
	return nil
}
