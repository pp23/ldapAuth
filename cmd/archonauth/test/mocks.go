package test

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type (
	LDAPString []byte
	LDAPDN     LDAPString
)

type LDAPResult struct {
	ResultCode        int
	MatchedDN         LDAPDN
	DiagnosticMessage LDAPString
}

func bytesToHexString(bytes []byte) string {
	if len(bytes) <= 0 {
		return ""
	}
	buf := new(strings.Builder)
	ber.PrintBytes(buf, bytes, " ")
	return buf.String()
}

// partly copied from https://github.com/bradfitz/gomemcache
type serverItem struct {
	flags   uint32
	data    []byte
	exp     time.Time // or zero value for no expiry
	casUniq uint64
}

type MockMemCache map[string]serverItem

func NewMockMemCache() MockMemCache {
	return make(MockMemCache)
}

func (mockMemcache MockMemCache) MockMemCachedMsgHandler(br *bufio.Reader, bw *bufio.Writer) error {
	writeRx := regexp.MustCompile(`^(set|add|replace|append|prepend|cas) (\S+) (\d+) (\d+) (\d+)(?: (\S+))?( noreply)?\r\n`)
	for {
		b, err := br.ReadSlice('\n')
		if err != nil {
			fmt.Printf("Read from connection: %v\r\n", err)
			return nil
		}
		line := string(b)
		fmt.Printf("string: %s", line)
		fmt.Printf("bytes2hex: %s", bytesToHexString(b))

		if strings.HasPrefix(line, "gets") {
			key := strings.Fields(strings.TrimPrefix(line, "gets "))[0]
			fmt.Printf("%s: [%s]", "gets", key)
			if val, ok := mockMemcache[key]; ok {
				fmt.Printf("%s: [%s]: %s", "gets", key, bytesToHexString(val.data))
				fmt.Fprintf(bw, "VALUE %s %d %d %d\r\n", key, val.flags, len(val.data), val.casUniq)
				bw.Write(val.data)
				bw.Write([]byte("\r\n"))
				bw.Write([]byte("END\r\n"))
				bw.Flush()
			} else {
				fmt.Printf("Key not found: %s. Current cache: %v", key, mockMemcache)
				for k := range mockMemcache {
					fmt.Printf("%s == %s : %v", key, k, key == k)
				}
			}
			continue
		}
		if m := writeRx.FindStringSubmatch(line); m != nil {
			verb, key, flagsStr, exptimeStr, lenStr, casUniq, noReply := m[1], m[2], m[3], m[4], m[5], m[6], strings.TrimSpace(m[7])
			flags, _ := strconv.ParseUint(flagsStr, 10, 32)
			exptimeVal, _ := strconv.ParseInt(exptimeStr, 10, 64)
			itemLen, _ := strconv.ParseInt(lenStr, 10, 32)
			fmt.Printf("got %q flags=%q exp=%d %d len=%d cas=%q noreply=%q", verb, key, flags, exptimeVal, itemLen, casUniq, noReply)
			body := make([]byte, itemLen+2)
			_, err := io.ReadFull(br, body)
			if err != nil {
				fmt.Printf("Could not read message body: %v", err)
				return err
			}
			fmt.Printf("body: %s", bytesToHexString(body[:itemLen]))
			mockMemcache[key] = serverItem{
				flags:   uint32(flags),
				data:    body[:itemLen],
				casUniq: 1,
				exp:     time.Unix(exptimeVal, 0),
			}
			fmt.Printf("%s: [%s]: %v (%s)", verb, key, body, string(body))
			bw.Write([]byte("STORED\r\n"))
			bw.Flush()
			continue
		}
		fmt.Printf("Unknown memcached command: %s", line)
	}
}

type MockTCPServer struct {
	hostport string
	l        net.Listener
	conns    []net.Conn
	stop     bool
	wg       sync.WaitGroup
}

type TesTCPPServer interface {
	Run(
		port uint16,
		msgHandler func(br *bufio.Reader, bw *bufio.Writer),
		errHandler func(error),
	) error
	Close()
}

func (mockTcpServer *MockTCPServer) Run(
	port uint16,
	msgHandler func(br *bufio.Reader, bw *bufio.Writer) error,
	errHandler func(error),
) error {
	mockTcpServer.stop = false
	mockTcpServer.hostport = ":" + strconv.Itoa(int(port))
	l, err := net.Listen("tcp", mockTcpServer.hostport)
	if err != nil {
		errHandler(err)
		return err
	}
	mockTcpServer.l = l
	for !mockTcpServer.stop {
		conn, err := l.Accept()
		if err != nil {
			// check if server was stopped anyway (the error resulted likely from a use of closed network connection)
			if mockTcpServer.stop {
				// errHandler(err) // usually not an error
				mockTcpServer.Close()
				break
			}
			errHandler(err)
			continue
		}
		fmt.Printf("New connection: %s", conn.RemoteAddr())
		mockTcpServer.conns = append(mockTcpServer.conns, conn)
		mockTcpServer.wg.Add(1)
		go func() {
			defer conn.Close()
			defer mockTcpServer.wg.Done()
			br := bufio.NewReader(conn)
			bw := bufio.NewWriter(conn)
			msgErr := msgHandler(br, bw)
			if msgErr != nil {
				if !errors.Is(msgErr, io.EOF) {
					fmt.Printf("msgHandler error %v", msgErr)
					errHandler(msgErr)
				} else {
					fmt.Printf("Ignoring error %v", msgErr)
				}
			}
		}()
	}
	return nil
}

func (mockTcpServer *MockTCPServer) Close() {
	mockTcpServer.stop = true
	if mockTcpServer.l == nil {
		fmt.Printf("Listener was already nil of %s", mockTcpServer.hostport)
	} else {
		mockTcpServer.l.Close()
	}
	for _, c := range mockTcpServer.conns {
		c.Close()
	}
	mockTcpServer.wg.Wait()
}

func MockBindResponse(br *bufio.Reader, bw *bufio.Writer) error {
	// build the LDAP Bind Response packet
	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 1, nil, "Bind Response")
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "resultCode"))
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagUTF8String, "cn=user02", "matchedDN"))
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagUTF8String, "test", "diagnosticMessage"))
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "MessageID"))
	envelope.AppendChild(pkt)

	bw.Write(envelope.Bytes())
	bw.Flush()
	return nil
}
