package aws

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quay/alas"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var _ driver.Updater = (*Updater)(nil)

// Updater implements the claircore.Updater.Fetcher and claircore.Updater.Parser
// interfaces making it eligible to be used as a claircore.Updater
type Updater struct {
	release Release
	// Timeout is applied to each network call.
	//
	// The default is 15 seconds.
	Timeout time.Duration `yaml:"timeout",json:"timeout"`
	// Mirrors is a list of URLs to use instead of fetching a mirrorlist.
	//
	// The layout of resources at the provided URLs is expected to be the same
	// as the upstream URLs.
	Mirrors []string `yaml:"mirrors",json:"mirrors"`

	client *Client
}

func NewUpdater(release Release) (*Updater, error) {
	return &Updater{
		release: release,
		Timeout: defaultOpTimeout,
	}, nil
}

func (u *Updater) Name() string {
	return fmt.Sprintf("aws-%v-updater", u.release)
}

func (u *Updater) Fetch(ctx context.Context, fingerprint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	// This two-step preserves the old client-per-call behavior if Configure
	// hasn't been called.
	client := u.client
	if client == nil {
		var err error
		client, err = NewClient(ctx, u.release)
		if err != nil {
			return nil, "", fmt.Errorf("failed to create client: %v", err)
		}
	}

	tctx, cancel := context.WithTimeout(ctx, u.Timeout)
	defer cancel()
	repoMD, err := client.RepoMD(tctx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to retrieve repo metadata: %v", err)
	}

	updatesRepoMD, err := repoMD.Repo(alas.UpdateInfo, "")
	if err != nil {
		return nil, "", fmt.Errorf("updates repo metadata could not be retrieved: %v", err)
	}

	tctx, cancel = context.WithTimeout(ctx, u.Timeout)
	defer cancel()
	rc, err := client.Updates(tctx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to retrieve update info: %v", err)
	}

	return rc, driver.Fingerprint(updatesRepoMD.Checksum.Sum), nil
}

func (u *Updater) Parse(ctx context.Context, contents io.ReadCloser) ([]*claircore.Vulnerability, error) {
	var updates alas.Updates
	err := xml.NewDecoder(contents).Decode(&updates)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal updates xml: %v", err)
	}
	dist := releaseToDist(u.release)

	vulns := []*claircore.Vulnerability{}
	for _, update := range updates.Updates {
		issued, err := time.Parse("2006-01-02 15:04", update.Issued.Date)
		if err != nil {
			return vulns, err
		}
		partial := &claircore.Vulnerability{
			Updater:            u.Name(),
			Name:               update.ID,
			Description:        update.Description,
			Issued:             issued,
			Links:              refsToLinks(update),
			Severity:           update.Severity,
			NormalizedSeverity: NormalizeSeverity(update.Severity),
			Dist:               dist,
		}
		vulns = append(vulns, u.unpack(partial, update.Packages)...)
	}

	return vulns, nil
}

// Configure implements driver.Configurable.
func (u *Updater) Configure(ctx context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
	if err := f(u); err != nil {
		return err
	}
	u.client = &Client{c: c}

	for _, m := range u.Mirrors {
		mu, err := url.Parse(m)
		if err != nil {
			return fmt.Errorf("failed to create client: %w", err)
		}
		u.client.mirrors = append(u.client.mirrors, mu)
	}
	if len(u.client.mirrors) == 0 {
		ctx, cancel := context.WithTimeout(ctx, u.Timeout)
		defer cancel()
		if err := u.client.getMirrors(ctx, u.release); err != nil {
			return fmt.Errorf("failed to create client: %w", err)
		}
	}

	return nil
}

// unpack takes the partially populated vulnerability and creates a fully populated vulnerability for each
// provided alas.Package
func (u *Updater) unpack(partial *claircore.Vulnerability, packages []alas.Package) []*claircore.Vulnerability {
	out := []*claircore.Vulnerability{}
	for _, alasPKG := range packages {
		// make copy
		v := *partial

		v.Package = &claircore.Package{
			Name: alasPKG.Name,
			Kind: "binary",
		}
		v.FixedInVersion = fmt.Sprintf("%s-%s", alasPKG.Version, alasPKG.Release)

		out = append(out, &v)
	}

	return out
}

// refsToLinks takes an alas.Update and creates a string with all the href links
func refsToLinks(u alas.Update) string {
	out := []string{}
	for _, ref := range u.References {
		out = append(out, ref.Href)
	}

	return strings.Join(out, " ")
}
