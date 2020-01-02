package ccpsecrets

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathConfig returns the path configuration for CRUD operations on the backend
// configuration.
func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: configPath + "$",
		Fields: map[string]*framework.FieldSchema{
			"host": {
				Type:        framework.TypeString,
				Description: `Host must be a host string, a host:port pair of the CCP Web Service.`,
				Required:    true,
			},
			"application_id": {
				Type:        framework.TypeString,
				Description: `Application Identifier identifies the secrets engine aginst the CCP Web Service.`,
				Required:    true,
			},
			"connection_timeout": {
				Type:        framework.TypeInt,
				Description: `The number of seconds that the Central Credential Provider will try to retrieve the password.`,
				Default:     30,
			},
			"fail_request_on_password_change": {
				Type:        framework.TypeBool,
				Description: `Fail the request during a password change`,
				Default:     false,
			},
			"client_cert": {
				Type:        framework.TypeString,
				Description: `The PEM enconded client certificate to autenticate Vault against the CCP Web Service`,
			},
			"client_key": {
				Type:        framework.TypeString,
				Description: `The PEM encoded client certificate key`,
			},
			"skip_tls_verify": {
				Type:        framework.TypeBool,
				Description: `Skip the verification of the CCP Web Service server certificate`,
				Default:     false,
			},
			"root_ca": {
				Type:        framework.TypeString,
				Description: `Root CA is a PEM encoded certificate or bundle to verify the CCP Web Service Server Certificate`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathConfigWrite,
			logical.CreateOperation: b.pathConfigWrite,
			logical.ReadOperation:   b.pathConfigRead,
		},

		HelpSynopsis:    confHelpSyn,
		HelpDescription: confHelpDesc,
	}
}

// pathConfigRead handles read commands to the config
func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entry, err := req.Storage.Get(ctx, configPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("configure the CCP client with config first"), nil
	}

	config := &clientConfig{}
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"host":                            config.Hostname,
			"application_id":                  config.ApplicationID,
			"connection_timeout":              config.ConnectionTimeout,
			"fail_request_on_password_change": config.FailRequestOnPasswordChange,
			"client_cert":                     string(config.ClientCert),
			"skip_tls_verify":                 config.SkipTLSVerify,
			"root_ca":                         string(config.RootCA),
		},
	}
	return resp, nil
}

// pathConfigWrite handles create and update commands to the config
func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	host := data.Get("host").(string)
	if len(host) == 0 {
		return logical.ErrorResponse("no host provided"), nil
	}
	applicationID := data.Get("application_id").(string)
	if len(applicationID) == 0 {
		return logical.ErrorResponse("no application_id provided"), nil
	}
	connectionTimeout := data.Get("connection_timeout").(int)
	if connectionTimeout < 0 {
		return logical.ErrorResponse("connection_timeout must be positive"), nil
	}

	config := &clientConfig{
		Hostname:                    host,
		ApplicationID:               applicationID,
		ConnectionTimeout:           connectionTimeout,
		FailRequestOnPasswordChange: data.Get("fail_request_on_password_change").(bool),
		ClientCert:                  []byte(data.Get("client_cert").(string)),
		ClientKey:                   []byte(data.Get("client_key").(string)),
		SkipTLSVerify:               data.Get("skip_tls_verify").(bool),
		RootCA:                      []byte(data.Get("root_ca").(string)),
	}

	client, err := createClient(config)
	if err != nil {
		return logical.ErrorResponse("unable to create the CCP client: %v", err), nil
	}

	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.ResetClient(client)

	return nil, nil
}

const confHelpSyn = `
Configure the CyberArk Credentials Provider API server and authentication information.
`
const confHelpDesc = `
This endpoint allows you to configure the connection to the CyberArk Credentials
Provider Web Service. Here you add or update a config. It takes immediate effect
on all subsequent actions.
`
