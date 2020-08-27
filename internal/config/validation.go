package config

import (
	"errors"
	"net/url"
)

const (
	InvalidLibraryPath = "'path' must be a valid absolute file url"
	MissingSlotLabel   = "the given given environment for 'SlotLabel' variables must be set"
	InvalidSecretName  = "secretName must be set"
)

func (c Config) Validate() error {
	if err := c.Library.validate(); err != nil {
		return err
	}
	return nil
}

func (l Pkcs11Library) validate() error {
	if l.Path == nil || l.Path.String() == "" || !isValidAbsFileUrl(l.Path) {
		return errors.New(InvalidLibraryPath)
	}
	if !l.SlotLabel.IsSet() {
		return errors.New(MissingSlotLabel)
	}
	return nil
}

func (c NewAccount) Validate() error {
	if c.SecretName == "" {
		return errors.New(InvalidSecretName)
	}
	return nil
}

func isValidAbsFileUrl(u *url.URL) bool {
	return u.Scheme == "file" && u.Host == "" && u.Path != ""
}
