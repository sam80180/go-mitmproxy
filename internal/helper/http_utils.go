package helper

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/hetiansu5/urlquery"
)

func BytesToRequest(data []byte) (*http.Request, error) {
	return http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
} // end BytesToRequest()

func HttpRequest[T any](method string, baseUrl string, path string, q any, headers *map[string]string, ioreader io.Reader, out *T) (int, []byte, error) {
	api_path := &url.URL{Path: path}
	if q != nil {
		queries, errV := urlquery.Marshal(q)
		if errV != nil {
			return http.StatusInternalServerError, nil, fmt.Errorf("failed to encode HTTP query string: %w", errV)
		} // end if
		api_path.RawQuery = string(queries)
	} // end if
	parsed_url, errU := url.Parse(baseUrl)
	if errU != nil {
		return http.StatusInternalServerError, nil, fmt.Errorf("failed to parse URL: %w", errU)
	} // end if
	u := parsed_url.ResolveReference(api_path)
	var req *http.Request
	var errN error = nil
	if ioreader != nil {
		req, errN = http.NewRequest(method, u.String(), ioreader)
	} else {
		req, errN = http.NewRequest(method, u.String(), nil)
	} // end if
	if errN != nil {
		return http.StatusInternalServerError, nil, fmt.Errorf("failed to create HTTP client: %w", errN)
	} // end if
	if headers != nil {
		for headerK, headerV := range *headers {
			req.Header.Add(headerK, headerV)
		} // end for
	} // end if
	var resp *http.Response
	var errDo error
	client := &http.Client{}
	resp, errDo = client.Do(req)
	if errDo != nil {
		return http.StatusInternalServerError, nil, fmt.Errorf("failed to call HTTP API '%s': %w", api_path.Path, errDo)
	} // end if
	defer resp.Body.Close()
	if out != nil {
		if errD := json.NewDecoder(resp.Body).Decode(out); errD != nil {
			return resp.StatusCode, nil, fmt.Errorf("failed to decode JSON response: %w", errD)
		} // end if
		return resp.StatusCode, nil, nil
	} // end if
	content, errIo := io.ReadAll(resp.Body)
	return resp.StatusCode, content, errIo
} // end HttpRequest()

func HttpGetRequest[T any](baseUrl string, path string, q any, headers *map[string]string, output *T) (int, []byte, error) {
	return HttpRequest(http.MethodGet, baseUrl, path, q, headers, nil, output)
} // end HttpGetRequest()

func EstimateHttpRequestSize(req *http.Request) int {
	// Start-line: METHOD SP REQUEST-URI SP HTTP/VERSION CRLF
	startLine := len(req.Method) + 1 + len(req.URL.RequestURI()) + len("HTTP/1.1") + 2

	// headers
	headerSize := 0
	for k, vv := range req.Header {
		for _, v := range vv {
			headerSize += len(k) + 2 + len(v) + 2 // "Key: Value\r\n"
		} // end for
	} // end for

	// Add Host header (Go adds Host implicitly, but it's part of actual request)
	if req.Host != "" {
		headerSize += len("Host") + 2 + len(req.Host) + 2
	} // end ifs
	headerSize += 2 // blank line
	bodySize := 0
	if req.ContentLength > 0 { // Body size if known
		bodySize = int(req.ContentLength)
	} // end if
	return startLine + headerSize + bodySize
} // end EstimateHttpRequestSize()

func EstimateHttpResponseSize(resp *http.Response) int {
	// Status-line: HTTP/VERSION SP STATUS-CODE SP REASON-PHRASE CRLF
	// resp.Status is e.g. "200 OK" → includes code, so subtract 4 chars ("200 ")
	statusLine := len("HTTP/1.1") + 1 + 3 + 1 + len(resp.Status) - 4 + 2

	headerSize := 0
	for k, vv := range resp.Header {
		for _, v := range vv {
			headerSize += len(k) + 2 + len(v) + 2
		} // end for
	} // end for
	headerSize += 2 // blank line
	bodySize := 0
	if resp.ContentLength > 0 { // body if Content-Length known
		bodySize = int(resp.ContentLength)
	} // end if
	return statusLine + headerSize + bodySize
} // end EstimateHttpResponseSize()
