package haproxy

import (
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
)

// This represents the default HTTP format and adds additional optional SSL information. Both the default and the modified version work.
// log-format %ci:%cp\ [%t]\ %ft\ %b/%s\ %Tq/%Tw/%Tc/%Tr/%Tt\ %ST\ %B\ %CC\ \%CS\ %tsc\ %ac/%fc/%bc/%sc/%rc\ %sq/%bq\ %hr\ %hs\ %{+Q}r\ %sslc/%sslv
var httpLogRegexp = &myRegexp{
	regexp.MustCompile(`(?P<ClientIp>[a-f0-9:\.]+):(?P<ClientPort>\d{1,5}) ` +
		`\[(?P<AcceptDate>\d{2}/\w{3}/\d{4}(:\d{2}){3}\.\d{3})\] ` +
		`(?P<FrontendName>\S+) (?P<BackendName>[\w-\.]+)/(?P<ServerName>\S+) ` +
		`(?P<Tq>(-1|\d+))/(?P<Tw>(-1|\d+))/(?P<Tc>(-1|\d+))/` +
		`(?P<Tr>(-1|\d+))/(?P<Tt>\+?\d+) ` +
		`(?P<HTTPStatusCode>(-1|\d{3})) (?P<BytesRead>\d+) ` +
		`(?P<CapturedRequestCookie>\S+) (?P<CapturedResponseCookie>\S+) ` +
		`(?P<TerminationState>[\w-]{4}) ` +
		`(?P<ActConn>\d+)/(?P<FeConn>\d+)/(?P<BeConn>\d+)/` +
		`(?P<SrvConn>\d+)/(?P<Retries>\d+) ` +
		`(?P<ServerQueue>\d+)/(?P<BackendQueue>\d+) ` +
		`(\{(?P<CapturedRequestHeaders>.*?)\} )?` +
		`(\{(?P<CapturedResponseHeaders>.*?)\} )?` +
		`"(?P<HTTPRequest>.+)"` +
		`( (?P<SslCipher>[\w-]+)/(?P<SslVersion>[\w\.]+))?`)}

func (l *Log) parseHTTP() error {
	decodeHook := mapstructure.ComposeDecodeHookFunc(
		stringToHTTPRequestHook,
		stringToTimeHook,
		mapstructure.StringToSliceHookFunc("|"),
	)
	return l.parseType(httpLogRegexp, decodeHook)
}

// This represents the default TCP format
// log-format %ci:%cp\ [%t]\ %ft\ %b/%s\ %Tw/%Tc/%Tt\ %B\ %ts\ %ac/%fc/%bc/%sc/%rc\ %sq/%bq
var tcpLogRegexp = &myRegexp{
	regexp.MustCompile(`(?P<ClientIp>[a-f0-9:\.]+):(?P<ClientPort>\d{1,5}) ` +
		`\[(?P<AcceptDate>\d{2}/\w{3}/\d{4}(:\d{2}){3}\.\d{3})\] ` +
		`(?P<FrontendName>\S+) (?P<BackendName>[\w-\.]+)/(?P<ServerName>\S+) ` +
		`(?P<Tw>(-1|\d+))/(?P<Tc>(-1|\d+))/(?P<Tt>\+?\d+) ` +
		`(?P<BytesRead>\d+) (?P<TerminationState>[\w-]{2}) ` +
		`(?P<ActConn>\d+)/(?P<FeConn>\d+)/(?P<BeConn>\d+)/` +
		`(?P<SrvConn>\d+)/(?P<Retries>\d+) ` +
		`(?P<ServerQueue>\d+)/(?P<BackendQueue>\d+)`)}

func (l *Log) parseTCP() error {
	return l.parseType(tcpLogRegexp, stringToTimeHook)
}

// This represents the default Error format
// doesn't have an explicit log-format, but basically looks like
// log-format %ci:%cp\ [%t]\ %f/<bind_name>: <message>
var errorLogRegexp = &myRegexp{
	regexp.MustCompile(`(?P<ClientIp>[a-f0-9:\.]+):(?P<ClientPort>\d{1,5}) ` +
		`\[(?P<AcceptDate>\d{2}/\w{3}/\d{4}(:\d{2}){3}\.\d{3})\] ` +
		`(?P<FrontendName>[\w-\.]+)/(?P<BindName>[\w-\.]+): ` +
		`(?P<Message>.*)`)}

func (l *Log) parseError() error {
	return l.parseType(errorLogRegexp, stringToTimeHook)
}

func stringToHTTPRequestHook(f reflect.Type, t reflect.Type, v interface{}) (interface{}, error) {
	if t == reflect.TypeOf(&HttpRequest{}) {
		// Split "POST /relative/path HTTP/1.1"
		vStr := v.(string)
		parts := strings.Split(vStr, " ")
		if len(parts) == 3 {
			u, _ := url.Parse(parts[1])
			v = &HttpRequest{Method: parts[0], URL: u, Version: parts[2]}
		} else if vStr == "<BADREQ>" {
			v = &HttpRequest{}
		}
	}
	return v, nil
}

func stringToTimeHook(f reflect.Type, t reflect.Type, v interface{}) (interface{}, error) {
	if t == reflect.TypeOf(time.Time{}) {
		const format = "02/Jan/2006:15:04:05.000"
		acceptDate, _ := time.Parse(format, v.(string))
		v = acceptDate
	}
	return v, nil
}
