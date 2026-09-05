package loader

import (
	"net/http"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

const testURL = "https://github.com/RTS-Framework/GRT-MXLoader"

func TestHTTP(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		payload := NewHTTP(testURL, nil)

		config, err := payload.Encode()
		require.NoError(t, err)

		spew.Dump(config)
	})

	t.Run("with options", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set("Header1", "h1")
		headers.Set("Header2", "h2")
		opts := &HTTPOptions{
			Headers:   headers,
			UserAgent: "ua",
			ProxyURL:  "http://127.0.0.1:8080/",
		}
		payload := NewHTTP(testURL, opts)

		config, err := payload.Encode()
		require.NoError(t, err)

		spew.Dump(config)
	})

	t.Run("invalid URL", func(t *testing.T) {
		payload := NewHTTP("invalid url", nil)

		config, err := payload.Encode()
		errStr := "parse \"invalid url\": invalid URI for request"
		require.EqualError(t, err, errStr)
		require.Nil(t, config)
	})

	t.Run("invalid proxy URL", func(t *testing.T) {
		opts := &HTTPOptions{
			ProxyURL: "invalid url",
		}
		payload := NewHTTP(testURL, opts)

		config, err := payload.Encode()
		errStr := "parse \"invalid url\": invalid URI for request"
		require.EqualError(t, err, errStr)
		require.Nil(t, config)
	})

	t.Run("mode", func(t *testing.T) {
		payload := NewHTTP(testURL, nil)
		require.Equal(t, ModeHTTP, payload.Mode())
	})
}
