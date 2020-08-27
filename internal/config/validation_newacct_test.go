package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func minimumValidNewAccountConfig() NewAccount {
	return NewAccount{
		SecretName: "secret",
	}
}

func TestNewAccount_Validate_MinimumValidConfig(t *testing.T) {
	err := minimumValidNewAccountConfig().Validate()
	require.NoError(t, err)
}

func TestNewAccount_Validate_SecretName_Invalid(t *testing.T) {
	var (
		conf    NewAccount
		err     error
		wantErr = InvalidSecretName
	)

	conf = minimumValidNewAccountConfig()
	conf.SecretName = ""
	err = conf.Validate()
	require.EqualError(t, err, wantErr)
}
