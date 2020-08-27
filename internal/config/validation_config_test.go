package config

import (
	"net/url"
	"quorum-account-plugin-pkcs-11/internal/testutil"
	"testing"

	"github.com/stretchr/testify/require"
)

func envVar(t *testing.T, envVarURL string) *EnvironmentVariable {
	u, err := url.Parse(envVarURL)
	require.NoError(t, err)
	env := EnvironmentVariable(*u)
	return &env
}

func minimumConfig(t *testing.T) Config {
	libPath, _ := url.Parse("file:///path/to/lib")
	slotLabel := envVar(t, "env://SLOT_LABEL")

	return Config{
		Library: Pkcs11Library{
			Path:      libPath,
			SlotLabel: slotLabel,
		},
	}
}

func TestVaultClient_Validate_MinimumValidConfig(t *testing.T) {
	defer testutil.UnsetAll()
	testutil.SetSlotLabel("my_label")

	vaultClient := minimumConfig(t)

	err := vaultClient.Validate()
	require.NoError(t, err)
}

func TestVaultClient_Validate_libpath_Valid(t *testing.T) {
	defer testutil.UnsetAll()
	testutil.SetSlotLabel("my_label")

	vaultUrls := []string{
		"file:///usr/local/lib/softhsm/libsofthsm2.so",
		"file:///usr/lib64/pkcs11/libsofthsm2.so",
	}
	for _, u := range vaultUrls {
		t.Run(u, func(t *testing.T) {
			config := minimumConfig(t)

			libPath, err := url.Parse(u)
			require.NoError(t, err)
			config.Library.Path = libPath

			gotErr := config.Validate()
			require.NoError(t, gotErr)
		})
	}
}

func TestVaultClient_Validate_libpath_Invalid(t *testing.T) {
	wantErrMsg := InvalidLibraryPath
	defer testutil.UnsetAll()
	testutil.SetSlotLabel("my_label")

	vaultUrls := []string{
		"",
		"noscheme",
		"http://vault",
		"https://vault:1111",
		"http://127.0.0.1:1111",
	}
	for _, u := range vaultUrls {
		t.Run(u, func(t *testing.T) {
			config := minimumConfig(t)

			libPath, err := url.Parse(u)
			require.NoError(t, err)
			config.Library.Path = libPath

			gotErr := config.Validate()
			require.EqualError(t, gotErr, wantErrMsg)
		})
	}
}

func TestVaultClient_Validate_slotlabel_Undefined(t *testing.T) {
	wantErrMsg := MissingSlotLabel
	config := minimumConfig(t)
	gotErr := config.Validate()
	require.EqualError(t, gotErr, wantErrMsg)
}
