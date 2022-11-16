package ccpsecrets

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"testing"

	logicaltest "github.com/hashicorp/vault/helper/testhelpers/logical"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/liviusnl/go-ccp/ccptest"
	"github.com/mitchellh/mapstructure"
)

func TestBackend(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		//	t.SkipNow()
	}
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	// Setup Mock Server
	ts := ccptest.NewCCPServer()
	defer ts.Close()

	logicaltest.Test(t, logicaltest.TestCase{
		LogicalBackend: b,
		Steps: []logicaltest.TestStep{
			testAccStepConfigWrite(t, ts, "MyApp"),
			testAccStepConfigRead(t, ts, "MyApp"),
			testAccStepObject(t, "/MySafe/MyObject"),
			testAccStepConfigWrite(t, ts, "OtherApp"),
			testAccStepConfigRead(t, ts, "OtherApp"),
			testAccStepObject(t, "/MySafe/MyFolder/MyObject"),
			testAccStepQuery(t, "MyUser"),
		},
	})

}

func testAccStepConfigWrite(t *testing.T, ts *ccptest.Server, applicationID string) logicaltest.TestStep {
	clientCert, clientKey := ts.ClientCertificate(applicationID)
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Data: map[string]interface{}{
			"host":           ts.Host,
			"application_id": applicationID,
			"client_cert":    clientCert,
			"client_key":     clientKey,
			"root_ca":        ts.ServerRootCA(),
		},
	}
}

func testAccStepConfigRead(t *testing.T, ts *ccptest.Server, applicationID string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      "config",
		Check: func(resp *logical.Response) error {
			var d struct {
				ApplicationID string `mapstructure:"application_id"`
				RootCA        string `mapstructure:"root_ca"`
			}
			if err := mapstructure.Decode(resp.Data, &d); err != nil {
				return err
			}

			if d.ApplicationID != applicationID {
				return fmt.Errorf("got %v: want %v", d.ApplicationID, applicationID)
			}

			if !bytes.Equal([]byte(d.RootCA), ts.ServerRootCA()) {
				return fmt.Errorf("got %v: want %v", d.RootCA, ts.ServerRootCA())
			}

			return nil
		},
	}
}

func testAccStepObject(t *testing.T, request string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      "object" + request,
		Data: map[string]interface{}{
			"username": request,
		},
		Check: func(resp *logical.Response) error {
			var d struct {
				Content string `mapstructure:"content"`
			}
			if err := mapstructure.Decode(resp.Data, &d); err != nil {
				return err
			}
			if len(d.Content) == 0 {
				return fmt.Errorf("Error retrieving content")
			}
			log.Printf("[WARN] Retrieved credentials: %v", d)

			return nil
		},
	}
}

func testAccStepQuery(t *testing.T, request string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      "query",
		Check: func(resp *logical.Response) error {
			var d struct {
				Content string `mapstructure:"content"`
			}
			if err := mapstructure.Decode(resp.Data, &d); err != nil {
				return err
			}
			if len(d.Content) == 0 {
				return fmt.Errorf("Error retrieving content")
			}
			log.Printf("[WARN] Retrieved credentials: %v", d)

			return nil
		},
	}
}
