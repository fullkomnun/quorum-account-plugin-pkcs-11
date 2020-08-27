package test

import (
	"errors"
	"testing"

	"github.com/hashicorp/go-plugin"
)

type ITContext struct {
	Client         *plugin.GRPCClient
	Server         *plugin.GRPCServer
	AccountManager *hashicorpPluginGRPCClient
}

// starts a plugin server and client, returning the client
func (c *ITContext) StartPlugin(t *testing.T) error {
	client, server := plugin.TestPluginGRPCConn(t, map[string]plugin.Plugin{
		"impl": new(testableHashicorpPlugin),
	})

	c.Client = client
	c.Server = server

	raw, err := client.Dispense("impl")
	if err != nil {
		return err
	}

	acctman, ok := raw.(hashicorpPluginGRPCClient)
	if !ok {
		return errors.New("unable to get plugin grpc client")
	}
	c.AccountManager = &acctman
	return nil
}

func (c *ITContext) Cleanup() {
	if c.Client != nil {
		c.Client.Close()
	}
	if c.Server != nil {
		c.Server.Stop()
	}
}
