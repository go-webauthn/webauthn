package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	bodyReadLimit  = 10 << 20
	bodyDrainLimit = 256 << 10
)

var errBodyTooLarge = fmt.Errorf("body exceeds the maximum size of %d bytes", bodyReadLimit)

var utf8BOM = []byte{0xef, 0xbb, 0xbf}

func drainAndClose(body io.ReadCloser) {
	_, _ = io.CopyN(io.Discard, body, bodyDrainLimit)
	_ = body.Close()
}

func decodeBody(body io.Reader, v any) (err error) {
	limited := &io.LimitedReader{R: body, N: bodyReadLimit + 1}
	decoder := json.NewDecoder(limited)

	if err = decoder.Decode(v); err != nil {
		if limited.N == 0 {
			return errBodyTooLarge
		}

		return err
	}

	_, err = decoder.Token()

	if limited.N == 0 {
		return errBodyTooLarge
	}

	if !errors.Is(err, io.EOF) {
		return errors.New("body contains trailing data")
	}

	return nil
}

func decodeBytes(data []byte, v any) (err error) {
	decoder := json.NewDecoder(bytes.NewReader(data))

	if err = decoder.Decode(v); err != nil {
		return err
	}

	_, err = decoder.Token()

	if !errors.Is(err, io.EOF) {
		return errors.New("body contains trailing data")
	}

	return nil
}

func parseCollectedClientData(data []byte, c *CollectedClientData) error {
	data = bytes.TrimPrefix(data, utf8BOM)

	if trimmed := bytes.TrimLeft(data, " \t\r\n"); len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("client data is not a JSON object")
	}

	return json.Unmarshal(data, c)
}
