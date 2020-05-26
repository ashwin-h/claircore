package driver

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/quay/claircore"
)

// Updater is an aggregate interface combining the method set of a Fetcher and a Parser
// and forces a Name() to be provided
type Updater interface {
	Name() string
	Fetcher
	Parser
}

// Parser is an interface which is embedded into the Updater interface.
//
// Parse should be called with an io.ReadCloser where the contents of a security
// advisory database can be read and parsed into a slice of
// *claircore.Vulnerability.
type Parser interface {
	// Parse should take an io.ReadCloser, read the contents, parse the contents
	// into a list of claircore.Vulnerability structs and then return
	// the list. Parse should assume contents are uncompressed and ready for parsing.
	Parse(ctx context.Context, contents io.ReadCloser) ([]*claircore.Vulnerability, error)
}

// Fetcher is an interface which is embedded into the Updater interface.
//
// When called, the method should determine if new security advisory data is
// available. A Fingerprint is provided in order for the Fetcher to determine if
// the contents have changed.
//
// If there is new content, Fetch should return an io.ReadCloser where the new
// content can be read.  A Fingerprint that uniquely identifies the new content
// should be returned as well.
//
// If the content has not changed, an Unchanged error should be returned.
type Fetcher interface {
	Fetch(context.Context, Fingerprint) (io.ReadCloser, Fingerprint, error)
}

// Unchanged is returned by Fetchers when the database has not changed.
var Unchanged = errors.New("database contents unchanged")

// Fingerprint is some identifying information about a vulnerability database.
type Fingerprint string

// ConfigUnmarshaler can be thought of as a curried Unmarshal function, or a
// Decode function. The function should populate a passed struct with any
// configuration information.
type ConfigUnmarshaler func(interface{}) error

// Configurable is an interface that Updaters can implement to opt-in to having
// their configuration provided dynamically.
type Configurable interface {
	Configure(context.Context, ConfigUnmarshaler, *http.Client) error
}
