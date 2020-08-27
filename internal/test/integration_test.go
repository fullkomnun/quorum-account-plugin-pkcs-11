package test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto"
	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto_common"
	"github.com/stretchr/testify/require"
	"quorum-account-plugin-pkcs-11/internal/config"
	"quorum-account-plugin-pkcs-11/internal/testutil"
	"strings"
	"testing"
)

func setupPlugin(t *testing.T, ctx *ITContext, args ...map[string]string) {
	err := ctx.StartPlugin(t)
	require.NoError(t, err)

	configBuilder := &ConfigBuilder{}
	configBuilder.
		WithLibraryPath(fmt.Sprintf("file://%v", "/usr/local/lib/softhsm/libsofthsm2.so")).
		WithSlotLabel(fmt.Sprintf("file://%v", "SLOT_LABEL")).
		WithSlotPIN(fmt.Sprintf("file://%v", "SLOT_PIN"))

	if args != nil {
		if unlock, ok := args[0]["unlock"]; ok {
			configBuilder.WithUnlock(strings.Split(unlock, ","))
		}
	}
	conf := configBuilder.Build(t)

	rawConf, err := json.Marshal(&conf)

	_, err = ctx.AccountManager.Init(context.Background(), &proto_common.PluginInitialization_Request{
		RawConfiguration: rawConf,
	})
	require.NoError(t, err)
}

func TestPlugin_Init_InvalidPluginConfig_libpath(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	err := ctx.StartPlugin(t)
	require.NoError(t, err)

	noLibPathConf := `{
	"library": {
		"path": ""
	}
}`

	_, err = ctx.AccountManager.Init(context.Background(), &proto_common.PluginInitialization_Request{
		RawConfiguration: []byte(noLibPathConf),
	})

	require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+config.InvalidLibraryPath)
}

func TestPlugin_Init_InvalidPluginConfig_slotlabel(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	err := ctx.StartPlugin(t)
	require.NoError(t, err)

	noLibPathConf := `{
	"library": {
		"path": "file:///usr/local/lib/softhsm/libsofthsm2.so"
	}
}`

	_, err = ctx.AccountManager.Init(context.Background(), &proto_common.PluginInitialization_Request{
		RawConfiguration: []byte(noLibPathConf),
	})

	require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+config.MissingSlotLabel)
}

func TestPlugin_Init_ValidPluginConfig(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	defer testutil.UnsetAll()
	testutil.SetSlotLabel("some label")
	testutil.SetSlotPIN("987654321")

	err := ctx.StartPlugin(t)
	require.NoError(t, err)

	noLibPathConf := `{
	"library": {
		"path": "file:///usr/local/lib/softhsm/libsofthsm2.so",
		"slotLabel": "env://SLOT_LABEL",
		"slotPin": "env://SLOT_PIN"
	}
}`

	_, err = ctx.AccountManager.Init(context.Background(), &proto_common.PluginInitialization_Request{
		RawConfiguration: []byte(noLibPathConf),
	})

	require.NoError(t, err)
}

func TestPlugin_Status_NoAccounts(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	defer testutil.UnsetAll()
	testutil.SetSlotLabel("Quorum Plugin Test 1")
	testutil.SetSlotPIN("123456")

	setupPlugin(t, ctx)
	_, err := ctx.AccountManager.Open(context.Background(), &proto.OpenRequest{})
	require.NoError(t, err)

	// Status
	resp, err := ctx.AccountManager.Status(context.Background(), &proto.StatusRequest{})
	require.NoError(t, err)

	require.Equal(t, "0 unlocked account(s)", resp.Status)
}

func TestPlugin_Accounts_NoAccounts(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	defer testutil.UnsetAll()
	testutil.SetSlotLabel("Quorum Plugin Test 1")
	testutil.SetSlotPIN("123456")

	setupPlugin(t, ctx)
	_, err := ctx.AccountManager.Open(context.Background(), &proto.OpenRequest{})
	require.NoError(t, err)

	// accounts
	resp, err := ctx.AccountManager.Accounts(context.Background(), &proto.AccountsRequest{})
	require.NoError(t, err)

	require.Len(t, resp.Accounts, 0)
}

func TestPlugin_Accounts_NewAccount(t *testing.T) {
	ctx := new(ITContext)
	defer ctx.Cleanup()

	defer testutil.UnsetAll()
	testutil.SetSlotLabel("Quorum Plugin Test 1")
	testutil.SetSlotPIN("123456")

	newAcctConf := `{
		"secretName": "newAcct"
	}`

	setupPlugin(t, ctx)
	_, err := ctx.AccountManager.Open(context.Background(), &proto.OpenRequest{})
	require.NoError(t, err)

	// NewAccount
	resp, err := ctx.AccountManager.NewAccount(context.Background(), &proto.NewAccountRequest{NewAccountConfig: []byte(newAcctConf)})
	require.NoError(t, err)

	require.NotNil(t, resp)
	require.Len(t, resp.Account.Address, 20)
}
