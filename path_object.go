package ccpsecrets

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	ccp "github.com/liviusnl/go-ccp"
)

const objectPathRegExp = objectPath + "/(?P<safe>[^/]+)/(?:(?P<folder>.*)/)?(?P<object>[^/]+)$"

// pathObject executes a request operation against the CCP Web Service
func pathObject(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: objectPathRegExp,
		Fields: map[string]*framework.FieldSchema{
			"safe": {
				Type:        framework.TypeString,
				Description: `The name of the Safe where the secret is stored.`,
			},
			"folder": {
				Type:        framework.TypeString,
				Description: ` the name of the folder where the secret is stored.`,
			},
			"object": {
				Type:        framework.TypeString,
				Description: `The name of the secret object to retrieve.`,
			},
			"reason": {
				Type:        framework.TypeString,
				Description: `The reason for retrieving the password.`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathObjectRead,
			},
		},

		HelpSynopsis:    objectHelpSyn,
		HelpDescription: objectHelpDesc,
	}
}

// pathObjectRead executes a CCP Object request
func (b *backend) pathObjectRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	client, err := b.Client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	r, logicalError, err := client.Request(ctx, &ccp.PasswordRequest{
		Safe:   data.Get("safe").(string),
		Folder: data.Get("folder").(string),
		Object: data.Get("object").(string),
		Reason: data.Get("reason").(string),
	})
	if err != nil {
		return nil, err
	}
	if len(logicalError) != 0 {
		return logical.ErrorResponse(logicalError), nil
	}

	mr, err := r.MapSnakeCase()
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: mr,
	}
	return resp, nil
}

const objectHelpSyn = `
Request a secret from the CyberArk Credetials Provider by Safe/Folder/Object
`
const objectHelpDesc = `
This endpoint allows you to request via the CyberArk Credentials Provider
Web Service secrets stored in the Enterprise Password Vault.
`
