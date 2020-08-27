package server

import (
	"github.com/hashicorp/go-plugin"
	"quorum-account-plugin-pkcs-11/internal/pkcs11"
)

type HashicorpPlugin struct {
	plugin.Plugin
	acctManager pkcs11.AccountManager
}
