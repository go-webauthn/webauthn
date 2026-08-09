package cached

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/go-webauthn/webauthn/metadata"
)

// New returns a new cached Provider given a set of functional [Option]'s. This provider will download a new version and
// save it to the configured file path if it doesn't exist or if it's out of date by default.
func New(opts ...Option) (provider metadata.Provider, err error) {
	p := &Provider{
		update: true,
		uri:    metadata.ProductionMDSURL,
	}

	for _, opt := range opts {
		if err = opt(p); err != nil {
			return nil, err
		}
	}

	if p.name == "" {
		return nil, fmt.Errorf("provider configured without setting a path for the cached file blob")
	}

	if p.newup == nil {
		p.newup = defaultNew
	}

	if p.decoder == nil {
		if p.decoder, err = metadata.NewDecoder(metadata.WithIgnoreEntryParsingErrors()); err != nil {
			return nil, err
		}
	}

	if p.clock == nil {
		p.clock = &metadata.RealClock{}
	}

	if err = p.init(); err != nil {
		return nil, err
	}

	return p, nil
}

// Provider implements a [metadata.Provider] with a file-based cache.
type Provider struct {
	metadata.Provider

	name    string
	uri     string
	update  bool
	force   bool
	clock   metadata.Clock
	client  *http.Client
	decoder *metadata.Decoder
	newup   NewFunc
}

func (p *Provider) init() (err error) {
	var mds *metadata.Metadata

	if !p.force {
		if mds, err = p.cached(); err != nil {
			return err
		}

		if mds != nil && !p.outdated(mds) {
			return p.setup(mds)
		}
	}

	var data []byte

	if data, err = p.get(); err != nil {
		return err
	}

	if mds, err = p.parseBytes(data); err != nil {
		return err
	}

	if err = doAtomicReplace(p.name, data); err != nil {
		return err
	}

	return p.setup(mds)
}

func (p *Provider) cached() (mds *metadata.Metadata, err error) {
	var f *os.File

	if f, err = os.Open(p.name); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, err
	}

	defer func() {
		_ = f.Close()
	}()

	return p.parse(f)
}

func (p *Provider) setup(mds *metadata.Metadata) (err error) {
	var provider metadata.Provider

	if provider, err = p.newup(mds); err != nil {
		return err
	}

	p.Provider = provider

	return nil
}

func (p *Provider) parse(r io.Reader) (data *metadata.Metadata, err error) {
	var payload *metadata.PayloadJSON

	if payload, err = p.decoder.Decode(r); err != nil {
		return nil, err
	}

	if data, err = p.decoder.Parse(payload); err != nil {
		return nil, err
	}

	return data, nil
}

func (p *Provider) parseBytes(data []byte) (mds *metadata.Metadata, err error) {
	var payload *metadata.PayloadJSON

	if payload, err = p.decoder.DecodeBytes(data); err != nil {
		return nil, err
	}

	if mds, err = p.decoder.Parse(payload); err != nil {
		return nil, err
	}

	return mds, nil
}

func (p *Provider) outdated(mds *metadata.Metadata) bool {
	return p.update && p.clock.Now().After(mds.Parsed.NextUpdate)
}

func (p *Provider) get() (data []byte, err error) {
	if p.client == nil {
		p.client = &http.Client{Timeout: metadata.DefaultMDSTimeout}
	}

	var res *http.Response

	if res, err = p.client.Get(p.uri); err != nil {
		return nil, err
	}

	defer func() {
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error occurred requesting metadata from '%s': unexpected status code %d", p.uri, res.StatusCode)
	}

	if data, err = io.ReadAll(res.Body); err != nil {
		return nil, fmt.Errorf("error occurred reading metadata response body from '%s': %w", p.uri, err)
	}

	return data, nil
}
