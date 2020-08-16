package ccpsecrets

import (
	"context"
	"regexp"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	ccp "github.com/liviusnl/go-ccp"
)

// pathQuery executes query operations against the CCP Web Service
func pathQuery(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: queryPath + "$",
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
			"username": {
				Type:        framework.TypeString,
				Description: `Search criteria according to the UserName account property.`,
			},
			"address": {
				Type:        framework.TypeString,
				Description: `Search criteria according to the Address account property.`,
			},
			"database": {
				Type:        framework.TypeString,
				Description: `Search criteria according to the Database account property.`,
			},
			"policy_id": {
				Type:        framework.TypeString,
				Description: "The format that will be used in the setPolicyID method.",
			},
			"reason": {
				Type:        framework.TypeString,
				Description: `The reason for retrieving the password.`,
			},
			"query_format": {
				Type:        framework.TypeString,
				Description: `Defines the query format, which can optionally use regular expressions.`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathQueryRead,
		},

		HelpSynopsis:    queryHelpSyn,
		HelpDescription: queryHelpDesc,
	}
}

// pathQueryRead executes a CCP Query request
func (b *backend) pathQueryRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	client, err := b.Client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	q := &ccp.PasswordRequest{
		Safe:     data.Get("safe").(string),
		Folder:   data.Get("folder").(string),
		Object:   data.Get("object").(string),
		UserName: data.Get("username").(string),
		Address:  data.Get("address").(string),
		Database: data.Get("database").(string),
		PolicyID: data.Get("policy_id").(string),
		Reason:   data.Get("reason").(string),
	}
	qfs := data.Get("query_format").(string)
	qf := ccp.QueryFormatExact
	if len(qfs) != 0 {
		re := regexp.MustCompile("^((?i)(?:exact)|(?:regex))$")
		format := re.FindStringSubmatch(qfs)
		if len(format) != 2 {
			return logical.ErrorResponse("invalid query_format: use exact or regex"), nil
		}
		switch strings.ToLower(format[1]) {
		case "exact":
			qf = ccp.QueryFormatExact
		case "regex":
			qf = ccp.QueryFormatRegEx
		}
	}

	r, logicalError, err := client.Query(q, qf)
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

const queryHelpSyn = `
Query the CyberArk Credetials Provider and retrieve a secret from the EPV
`
const queryHelpDesc = `
This endpoint allows you to query via the CyberArk Credentials Provider
Web Service secrets stored in the Enterprise Password Vault.
`
