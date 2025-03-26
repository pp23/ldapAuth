package test

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
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
			return err
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
	var l net.Listener
	var errListener error
	// simple retry if port from previous server instance not immediately available
	for i := 0; i < 3; i++ {
		l, errListener = net.Listen("tcp", mockTcpServer.hostport)
		if errListener == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if errListener != nil {
		errHandler(errListener)
		return errListener
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
			var msgErr error
			for msgErr = nil; msgErr == nil; {
				msgErr = msgHandler(br, bw)
			}
			if msgErr != nil {
				if !errors.Is(msgErr, io.EOF) && !errors.Is(msgErr, net.ErrClosed) {
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

const (
	BEGIN_LDAPMESSAGE_SEQ             = 1
	BEGIN_BIND_REQUEST_PROTOCOL_OP    = 2
	BEGIN_SEARCH_REQUEST_PROTOCOL_OP  = 3
	BEGIN_SET_OF_REQUESTED_ATTRIBUTES = 4
)

func MockLdapResponse(br *bufio.Reader, bw *bufio.Writer) error {
	// read the LDAP request
	state := 0
	lop := 0
	msgLen := math.MaxInt
	for l := 0; l < msgLen; {
		log.Printf("Read %d/%d", l, msgLen)
		b, err := br.ReadByte()
		if err != nil {
			return err
		}
		log.Printf("Read byte: %x", b)
		switch b {
		case 0x30: // Sequence
			b2, err := br.ReadByte()
			if err != nil {
				return err
			}
			if msgLen == math.MaxInt {
				msgLen = int(b2)
			}
			// if sequence is a part of an op, decrement the >0 length of the op (lop) accordingly
			if lop > 0 {
				lop -= 2 // code + length
			}
			if state == BEGIN_SEARCH_REQUEST_PROTOCOL_OP {
				state = BEGIN_SET_OF_REQUESTED_ATTRIBUTES
			} else {
				state = BEGIN_LDAPMESSAGE_SEQ
			}
			log.Printf("%x %x -- Begin the LDAPMessage sequence || %d", b, b2, state)
		case 0x02:
			s, err := br.ReadByte()
			if err != nil {
				return err
			}
			l++
			i := make([]byte, s)
			n, err2 := br.Read(i)
			if err2 != nil {
				return err2
			}
			l += n
			switch state {
			case BEGIN_LDAPMESSAGE_SEQ:
				log.Printf("%x %x -- The message ID", b, i)
			case BEGIN_BIND_REQUEST_PROTOCOL_OP:
				log.Printf("%x %x -- The LDAP protocol version", b, i)
				lop -= 2 // code + length
				lop -= n
			case BEGIN_SEARCH_REQUEST_PROTOCOL_OP:
				// time/size limit
				lop -= 2 // code + length
				lop -= n
			}
		case 0x60: // Bind request
			s, err := br.ReadByte()
			if err != nil {
				return nil
			}
			l++
			lop = int(s)
			log.Printf("%x %x -- Begin the bind request protocol op", b, s)
			state = BEGIN_BIND_REQUEST_PROTOCOL_OP
		case 0x63: // search request
			s, err := br.ReadByte()
			if err != nil {
				return nil
			}
			l++
			lop = int(s)
			log.Printf("%x %x -- Begin the search request protocol op", b, s)
			state = BEGIN_SEARCH_REQUEST_PROTOCOL_OP
		case 0xa: // wholeSubtree scope
			s, err := br.ReadByte()
			if err != nil {
				return nil
			}
			l++
			lop -= 2 // code + length
			opBuf := make([]byte, s)
			// discard contents as this is only a mocking where we respond static data
			n, err2 := br.Read(opBuf)
			if err2 != nil {
				return err2
			}
			l += n
			lop -= n
			log.Printf("n: %d, lop: %d", n, lop)
			log.Printf("%x -- ", b)
		case 0xa0: // begin an and filter
			s, err := br.ReadByte()
			if err != nil {
				return nil
			}
			l++
			lop -= 2 // code + length
			log.Printf("%x %x -- Begin an and filter", b, s)
		case 0xa3: // begin an equality filter
			s, err := br.ReadByte()
			if err != nil {
				return nil
			}
			l++
			lop -= 2 // code + length
			opBuf := make([]byte, s)
			// discard contents as this is only a mocking where we respond static data
			n, err2 := br.Read(opBuf)
			if err2 != nil {
				return err2
			}
			l += n
			lop -= n
			log.Printf("n: %d, lop: %d", n, lop)
			log.Printf("%x %x -- Begin an equality filter: %s", b, s, string(opBuf))
		case 0x87: // present filter
			s, err := br.ReadByte()
			if err != nil {
				return nil
			}
			l++
			lop -= 2 // code + length
			opBuf := make([]byte, s)
			// discard contents as this is only a mocking where we respond static data
			n, err2 := br.Read(opBuf)
			if err2 != nil {
				return err2
			}
			l += n
			lop -= n
			log.Printf("n: %d, lop: %d", n, lop)
			log.Printf("%x %x -- Present filter: %s", b, s, string(opBuf))
		case 0x01: // typesOnly flag
			log.Printf("lop: %d", lop)
			s, err := br.ReadByte()
			if err != nil {
				return err
			}
			l++
			lop -= 2 // code + length
			opBuf := make([]byte, s)
			// discard contents as this is only a mocking where we respond static data
			n, err2 := br.Read(opBuf)
			if err2 != nil {
				return err2
			}
			l += n
			lop -= n
			log.Printf("n: %d, lop: %d", n, lop)
		case 0x04: // octet string
			log.Printf("lop: %d", lop)
			s, err := br.ReadByte()
			if err != nil {
				return err
			}
			l++
			lop -= 2 // code + length
			opBuf := make([]byte, s)
			// discard contents as this is only a mocking where we respond static data
			n, err2 := br.Read(opBuf)
			if err2 != nil {
				return err2
			}
			l += n
			lop -= n
			log.Printf("n: %d, lop: %d", n, lop)
			// complete op read?
			if lop <= 0 {
				switch state {
				case BEGIN_BIND_REQUEST_PROTOCOL_OP:
					log.Printf("%x %x %x -- Bind DN", b, s, opBuf)
					return MockBindResponse(br, bw)
				case BEGIN_SET_OF_REQUESTED_ATTRIBUTES:
					return MockSearchResponse(br, bw)
				default:
					return fmt.Errorf("ERROR: Unknown state %d", state)
				}
			}
		case 0x80:
			log.Printf("lop: %d", lop)
			s, err := br.ReadByte()
			if err != nil {
				return err
			}
			l++
			lop -= 2 // code + length
			opBuf := make([]byte, s)
			// discard contents as this is only a mocking where we respond static data
			n, err2 := br.Read(opBuf)
			if err2 != nil {
				return err2
			}
			l += n
			lop -= n
			log.Printf("n: %d, lop: %d", n, lop)
			// complete op read?
			if lop <= 0 {
				switch state {
				case BEGIN_BIND_REQUEST_PROTOCOL_OP:
					log.Printf("%x %x %x -- Empty password", b, s, opBuf)
					return MockBindResponse(br, bw)
				default:
					log.Printf("ERROR: Unknown state %d", state)
				}
			}
		default:
			log.Printf("Unknown LDAP request: %x %d/%d", b, l, msgLen)
			// no msgLen set. Can happen, if new LDAPMessage Sequence came in.
			if msgLen == math.MaxInt {
				return fmt.Errorf("Unknown LDAPMessage sequence %x", b)
			}
			return fmt.Errorf("Unknown LDAP request: %x", b)
		}
	}
	return nil
}

// mocks a search result entry. Generated by ChatGPT.
func buildSearchResultEntry(messageID int) *ber.Packet {
	dn := "cn=alice,dc=example,dc=com"

	attrName := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "Attribute Name")
	attrValue := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "alice", "Attribute Value")
	attrSet := ber.NewSequence("Attribute Value Set")
	attrSet.AppendChild(attrValue)

	partialAttribute := ber.NewSequence("PartialAttribute")
	partialAttribute.AppendChild(attrName)
	partialAttribute.AppendChild(attrSet)

	attributes := ber.NewSequence("Attributes")
	attributes.AppendChild(partialAttribute)

	searchResultEntry := ber.NewSequence("SearchResultEntry")
	searchResultEntry.Tag = ber.Tag(4) // APPLICATION 4
	searchResultEntry.ClassType = ber.ClassApplication
	searchResultEntry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "ObjectName"))
	searchResultEntry.AppendChild(attributes)

	message := ber.NewSequence("LDAPMessage")
	message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))
	message.AppendChild(searchResultEntry)
	return message
}

// mocks a search result done. Generated by ChatGPT.
func buildSearchResultDone(messageID int) *ber.Packet {
	searchResultDone := ber.NewSequence("SearchResultDone")
	searchResultDone.Tag = ber.Tag(5) // APPLICATION 5
	searchResultDone.ClassType = ber.ClassApplication
	searchResultDone.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "resultCode (success)"))
	searchResultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	searchResultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))

	message := ber.NewSequence("LDAPMessage")
	message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))
	message.AppendChild(searchResultDone)
	return message
}

// sends LDAP response packets. Generated by ChatGPT.
func sendLDAPResponse(w *bufio.Writer, packets ...*ber.Packet) error {
	for _, packet := range packets {
		_, err := w.Write(packet.Bytes())
		if err != nil {
			return err
		}
		err = w.Flush()
		if err != nil {
			return err
		}
	}
	return nil
}

func MockSearchResponse(br *bufio.Reader, bw *bufio.Writer) error {
	// build the LDAP Search Response packet, see https://ldap.com/ldapv3-wire-protocol-reference-search/
	entry := buildSearchResultEntry(2)
	done := buildSearchResultDone(2)
	err := sendLDAPResponse(bw, entry, done)
	if err != nil {
		return err
	}
	return io.EOF // signal we have done
}

func MockBindResponse(br *bufio.Reader, bw *bufio.Writer) error {
	// build the LDAP Bind Response packet, see https://ldap.com/ldapv3-wire-protocol-reference-bind/
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
