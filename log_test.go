package haproxy_test

import (
	"testing"

	"github.com/chrishoffman/haproxylog"
	"github.com/stretchr/testify/assert"
)

func Test_ParseNoMatch_ReturnsNilAndError(t *testing.T) {
	log, err := haproxy.NewLog("Not a haproxy syslog message")

	assert.Nil(t, log, "Nil return when unable to determine type")
	assert.NotNil(t, err, "Error returned when unable to determine type")
}

func Test_HTTPLog_ReturnsLog(t *testing.T) {
	haproxyLog := `192.168.9.185:56276 [29/May/2015:10:36:47.766] Service1~ Service1/host-1 2/0/0/10/12 200 423 - - ---- 282/36/0/0/0 0/0 {d7d9b784-4276-42bc-ae79-71e9e84d2b85} {d7d9b784-4276-42bc-ae79-71e9e84d2b85} "POST /path/to/app HTTP/1.1" ECDHE-RSA-AES128-GCM-SHA256/TLSv1.2`

	log, err := haproxy.NewLog(haproxyLog)
	assert.NotNil(t, log, "log returns HaproxyHTTPLog")
	assert.Nil(t, err, "No error return")

	assert.Equal(t, "POST", log.HTTPRequest.Method, "HTTPRequest method is POST")
	assert.Equal(t, "192.168.9.185", log.ClientIP, "ClientIP address matches log")
	assert.Equal(t, int64(200), log.HTTPStatusCode, "HTTP Status Code is 200")
}

func Test_HTTPLogNoResponseHeaders_ReturnsLog(t *testing.T) {
	haproxyLog := `192.168.9.185:56276 [29/May/2015:10:36:47.766] Service1~ Service1/host-1 2/0/0/10/12 200 423 - - ---- 282/36/0/0/0 0/0 {d7d9b784-4276-42bc-ae79-71e9e84d2b85} "POST /path/to/app HTTP/1.1" ECDHE-RSA-AES128-GCM-SHA256/TLSv1.2`

	log, err := haproxy.NewLog(haproxyLog)
	assert.Nil(t, err, "No error return")
	assert.Equal(t, log.GetFormat(), haproxy.HTTP)
	assert.Equal(t, "POST", log.HTTPRequest.Method, "HTTPRequest method is POST")
	assert.Equal(t, "192.168.9.185", log.ClientIP, "ClientIP address matches log")
	assert.Equal(t, int64(200), log.HTTPStatusCode, "HTTP Status Code is 200")
}

func Test_HTTPLogNoHeaders_ReturnsLog(t *testing.T) {
	haproxyLog := `192.168.9.185:56276 [29/May/2015:10:36:47.766] Service1~ Service1/host-1 2/0/0/10/12 200 423 - - ---- 282/36/0/0/0 0/0 "POST /path/to/app HTTP/1.1" ECDHE-RSA-AES128-GCM-SHA256/TLSv1.2`

	log, err := haproxy.NewLog(haproxyLog)
	assert.NotNil(t, log, "log returns Log")
	assert.Nil(t, err, "No error return")
}

func Test_HTTPLogNoSSLInfo_ReturnsLog(t *testing.T) {
	haproxyLog := `192.168.9.185:56276 [29/May/2015:10:36:47.766] Service1~ Service1/host-1 2/0/0/10/12 200 423 - - ---- 282/36/0/0/0 0/0 {d7d9b784-4276-42bc-ae79-71e9e84d2b85} {d7d9b784-4276-42bc-ae79-71e9e84d2b85} "POST /path/to/app HTTP/1.1"`

	log, err := haproxy.NewLog(haproxyLog)
	assert.NotNil(t, log, "log returns HaproxyHTTPLog")
	assert.Nil(t, err, "No error return")
}

func Test_HTTPLogHttpRequestDecodeError_ReturnsError(t *testing.T) {
	haproxyLog := `192.168.9.185:56276 [29/May/2015:10:36:47.766] Service1~ Service1/host-1 2/0/0/10/12 200 423 - - ---- 282/36/0/0/0 0/0 {d7d9b784-4276-42bc-ae79-71e9e84d2b85} {d7d9b784-4276-42bc-ae79-71e9e84d2b85} "POST /path/to/app" ECDHE-RSA-AES128-GCM-SHA256/TLSv1.2`
	log, err := haproxy.NewLog(haproxyLog)
	assert.Nil(t, log, "Invalid decode of object returns nil")
	assert.NotNil(t, err, "Invalid log line returns an error")
}

func Test_HTTPLogHttpRequestBadReq_ReturnsLog(t *testing.T) {
	haproxyLog := `192.168.9.185:56276 [29/May/2015:10:36:47.766] Service1~ Service1/host-1 2/0/0/10/12 200 423 - - ---- 282/36/0/0/0 0/0 {d7d9b784-4276-42bc-ae79-71e9e84d2b85} {d7d9b784-4276-42bc-ae79-71e9e84d2b85} "<BADREQ>" ECDHE-RSA-AES128-GCM-SHA256/TLSv1.2`
	log, err := haproxy.NewLog(haproxyLog)
	assert.NotNil(t, log, "log returns HaproxyHTTPLog")
	assert.Nil(t, err, "No error return")
}

func Test_TCPLog_ReturnsLog(t *testing.T) {
	haproxyLog := `192.168.9.185:56276 [29/May/2015:10:36:47.766] Service1 Service1/host-1 2/0/0 423 -- 282/36/0/0/0 0/0`
	log, err := haproxy.NewLog(haproxyLog)
	assert.NotNil(t, log, "log returns Log")
	assert.Nil(t, err, "No Error")
	assert.Equal(t, log.GetFormat(), haproxy.TCP)
	assert.Equal(t, log.ServerName, "host-1")
}

func Test_ErrorLog_ReturnsLog(t *testing.T) {
	haproxyLog := `192.168.9.185:56276 [29/May/2015:10:36:47.766] Service1/bind-1: We have a problem here`
	log, err := haproxy.NewLog(haproxyLog)
	assert.NotNil(t, log, "log returns Log")
	assert.Nil(t, err, "No Error")
	assert.Equal(t, log.GetFormat(), haproxy.Error)
	assert.Equal(t, log.Message, "We have a problem here")
}

func Test_MatchHTTPLogSignatureRegexpFails_ReturnsError(t *testing.T) {
	haproxyLog := `192.168.9.185:56276 [29/May/2015:10:36:47.766] Service1~ Service1/host-1 2/0/0/10/12 200 423 - - ---- 282/36/0/0/0 0/0`
	log, err := haproxy.NewLog(haproxyLog)
	assert.Nil(t, log, "Nil return when unable to parse log")
	assert.NotNil(t, err, "Error returned when unable to parse log")
}
