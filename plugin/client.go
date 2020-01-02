package ccpsecrets

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"

	"github.com/hashicorp/vault/sdk/logical"
	ccp "github.com/liviusnl/go-ccp"
)

// ccpConfig containt the configuration for the CCP client
type clientConfig struct {
	// The hostname of CCP Web Service host.
	// This should be a hostname with an optipnal port number.
	// Using the format: hostname[:port]
	Hostname string `json:hostname`
	// The ID of the application performaing the password request
	ApplicationID string `json:application_id`
	// The number of seconds that the Central Credential Provider
	// will try to retrieve the password. The timeout is calculated
	// when the request is sent from the web service to the Vault
	// and returned back to the web service.
	// If zero the default connection timeout will be used.
	ConnectionTimeout int `json:connection_timeout`
	// Whether or not an error will be returned, if this web service
	// is called when a password change process is underway.
	// To fail a request Aduring a password change, set this value to true
	FailRequestOnPasswordChange bool `json:fail_request_on_password_change`
	// ClientCert it the PEM encoded Client Side Certificate used to
	// authenticate against the CCP Web Service
	ClientCert []byte `json:client_cert`
	// ClientCertKey is the PEM encoded Client Side Certificate key used
	// to authenticate against the CCP Web Service
	ClientKey []byte `json:client_cert_key`
	// SkipTLSVerify disbles or enables service certificate Validation
	SkipTLSVerify bool `json:skip_tls_verify`
	// RootCAs is a PEM encoded certificate or bundle to verify the
	// CCP Web Service Server Certificate
	RootCA []byte `json:root_ca`
}

// Create a new CCP Client
func createClient(c *clientConfig) (*ccp.Client, error) {
	var cert tls.Certificate
	switch {
	case len(c.ClientCert) != 0 && len(c.ClientKey) != 0:
		var err error
		cert, err = tls.X509KeyPair(c.ClientCert, c.ClientKey)
		if err != nil {
			return nil, err
		}
	case len(c.ClientCert) != 0 || len(c.ClientKey) != 0:
		return nil, errors.New("both client_cert and client_key must be provided")
	}
	var rootCAs *x509.CertPool
	if len(c.RootCA) != 0 {
		rootCAs := x509.NewCertPool()
		ok := rootCAs.AppendCertsFromPEM(c.RootCA)
		if !ok {
			return nil, errors.New("unable to parse the certificate(s) in root_ca")
		}
	}

	client, err := ccp.NewClient(&ccp.Config{
		Hostname:                    c.Hostname,
		ApplicationID:               c.ApplicationID,
		ConnectionTimeout:           c.ConnectionTimeout,
		FailRequestOnPasswordChange: c.FailRequestOnPasswordChange,
		Certificate:                 &cert,
		SkipTLSVerify:               c.SkipTLSVerify,
		RootCAs:                     rootCAs,
	})
	if err != nil {
		return nil, err
	}
	return client, nil
}

// Client returns the CCP Client.
func (b *backend) Client(ctx context.Context, s logical.Storage) (*ccp.Client, error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	if b.client != nil {
		return b.client, nil
	}

	entry, err := s.Get(ctx, configPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, errors.New("configure the CCP client with config first")
	}

	config := &clientConfig{}
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}

	client, err := createClient(config)

	b.client = client
	return client, err
}

// ResetClient forces a new client next time Client() is called.
func (b *backend) ResetClient(newClient *ccp.Client) {
	b.lock.Lock()
	defer b.lock.Unlock()

	if b.client != nil {
		b.client.Close()
	}

	b.client = newClient
}
