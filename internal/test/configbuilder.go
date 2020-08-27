package test

import (
	"net/url"
	"quorum-account-plugin-pkcs-11/internal/config"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ConfigBuilder struct {
	libraryPath string
	slotLabel   string
	slotPIN     string
	unlock      []string
}

func (b *ConfigBuilder) WithLibraryPath(s string) *ConfigBuilder {
	b.libraryPath = s
	return b
}

func (b *ConfigBuilder) WithSlotLabel(s string) *ConfigBuilder {
	b.slotLabel = s
	return b
}

func (b *ConfigBuilder) WithSlotPIN(s string) *ConfigBuilder {
	b.slotPIN = s
	return b
}

func (b *ConfigBuilder) WithUnlock(s []string) *ConfigBuilder {
	b.unlock = s
	return b
}

func (b *ConfigBuilder) Build(t *testing.T) config.Config {
	var err error

	var path *url.URL
	if b.libraryPath != "" {
		path, err = url.Parse(b.libraryPath)
		assert.NoError(t, err)
	}

	var slotLabelEnv config.EnvironmentVariable
	if b.slotLabel != "" {
		slotLabel, err := url.Parse(b.slotLabel)
		assert.NoError(t, err)
		slotLabelEnv = config.EnvironmentVariable(*slotLabel)
	}

	var slotPinEnv config.EnvironmentVariable
	if b.slotPIN != "" {
		slotPin, err := url.Parse(b.slotPIN)
		assert.NoError(t, err)
		slotPinEnv = config.EnvironmentVariable(*slotPin)
	}

	return config.Config{
		Library: config.Pkcs11Library{
			Path:      path,
			SlotLabel: &slotLabelEnv,
			SlotPin:   &slotPinEnv,
		},
		Unlock: b.unlock,
	}
}
