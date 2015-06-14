package haproxy

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
)

// LogFormat is an enumeration containing the available formats for
// HAProxy log messages
type LogFormat int

const (
	// HTTP log format
	HTTP LogFormat = iota
	// TCP log format
	TCP
	// Error log format
	Error
	// Unknown log format
	Unknown
)

// Log contains all the available fields from the HAProxy logs.  All fields from
// the HTTP, TCP, and Error log formats are available.
type Log struct {
	raw    string
	format LogFormat

	// Common Fields
	ClientIP     string
	ClientPort   int64
	AcceptDate   time.Time
	FrontendName string

	// HTTP/TCP Fields
	BackendName      string
	ServerName       string
	Tw               int64
	Tc               int64
	Tt               int64
	BytesRead        int64
	TerminationState string
	ActConn          int64
	FeConn           int64
	BeConn           int64
	SrvConn          int64
	Retries          int64
	ServerQueue      int64
	BackendQueue     int64

	// HTTP Fields
	Tq                      int64
	Tr                      int64
	HTTPStatusCode          int64
	CapturedRequestCookie   string
	CapturedResponseCookie  string
	CapturedRequestHeaders  []string
	CapturedResponseHeaders []string
	HTTPRequest             *HttpRequest
	SslCipher               string
	SslVersion              string

	// Error Fields
	BindName string
	Message  string
}

type HttpRequest struct {
	Method  string
	URL     *url.URL
	Version string
}

// NewLog identifies the type and parses a raw HAProxy log line and returns
// a Log struct
func NewLog(rawLog string) (*Log, error) {
	return new(rawLog, identifyFormat(rawLog))
}

func new(rawLog string, logFormat LogFormat) (*Log, error) {
	log := &Log{raw: rawLog, format: logFormat}

	err := log.parse()
	if err != nil {
		return nil, err
	}

	return log, nil
}

// GetFormat returns the LogType for the log line
func (l *Log) GetFormat() LogFormat {
	return l.format
}

// Parse populates the Log struct based on the LogType
func (l *Log) parse() error {
	switch l.format {
	case HTTP:
		return l.parseHTTP()
	case TCP:
		return l.parseTCP()
	case Error:
		return l.parseError()
	default:
		return errors.New("Unable to parse log message of Unknown type")
	}
}

// This function determines the log type through simpler signatures instead
// of running through the regular expressions until one is found
func identifyFormat(rawLog string) LogFormat {
	parts := strings.Split(rawLog, " ")

	partsLen := len(parts)
	if partsLen > 4 {
		stats := strings.Split(parts[4], "/")

		switch len(stats) {
		case 5:
			return HTTP
		case 3:
			return TCP
		}
	}

	if partsLen > 2 {
		if strings.Contains(parts[2], "/") {
			return Error
		}
	}

	return Unknown
}

func (l *Log) parseType(r *myRegexp, decodeHook mapstructure.DecodeHookFunc) error {
	parsed := r.FindStringSubmatchMap(l.raw)
	if len(parsed) == 0 {
		return fmt.Errorf("Unable to parse log message: %s", l.raw)
	}

	config := &mapstructure.DecoderConfig{
		WeaklyTypedInput: true,
		Result:           l,
		DecodeHook:       decodeHook,
	}

	decoder, _ := mapstructure.NewDecoder(config)
	err := decoder.Decode(parsed)
	if err != nil {
		return err
	}
	return nil
}
