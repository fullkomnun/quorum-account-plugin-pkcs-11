package config

import (
	"encoding/json"
	"net/url"
	"os"
)

type Config struct {
	Library Pkcs11Library
	Unlock  []string
}

type Pkcs11Library struct {
	Path      *url.URL
	SlotLabel *EnvironmentVariable

	// Optional Slot Login
	SlotPin *EnvironmentVariable
}

type NewAccount struct {
	SecretName string
}

type configJSON struct {
	Library pkcs11LibraryJSON
	Unlock  []string
}

type pkcs11LibraryJSON struct {
	Path      string
	SlotLabel string
	SlotPin   string
}

func (c *Config) UnmarshalJSON(b []byte) error {
	j := new(configJSON)
	if err := json.Unmarshal(b, j); err != nil {
		return err
	}
	vc, err := j.config()
	if err != nil {
		return err
	}
	*c = vc
	return nil
}

func (c configJSON) config() (Config, error) {
	library, err := c.Library.pkcs11Library()
	if err != nil {
		return Config{}, err
	}

	return Config{
		Library: library,
		Unlock:  c.Unlock,
	}, nil
}

func (l pkcs11LibraryJSON) pkcs11Library() (Pkcs11Library, error) {
	path, err := url.Parse(l.Path)
	if err != nil {
		return Pkcs11Library{}, err
	}
	slotLabel, err := url.Parse(l.SlotLabel)
	if err != nil {
		return Pkcs11Library{}, err
	}
	slotPIN, err := url.Parse(l.SlotPin)
	if err != nil {
		return Pkcs11Library{}, err
	}

	var (
		slotLabelEnv = EnvironmentVariable(*slotLabel)
		slotPINEnv   = EnvironmentVariable(*slotPIN)
	)

	return Pkcs11Library{
		Path:      path,
		SlotLabel: &slotLabelEnv,
		SlotPin:   &slotPINEnv,
	}, nil
}

func (c *Config) MarshalJSON() ([]byte, error) {
	j, err := c.configJSON()
	if err != nil {
		return nil, err
	}
	return json.Marshal(j)
}

func (c Config) configJSON() (configJSON, error) {
	library, err := c.Library.pkcs11LibraryJSON()
	if err != nil {
		return configJSON{}, err
	}
	return configJSON{
		Library: library,
		Unlock:  c.Unlock,
	}, nil
}

func (l Pkcs11Library) pkcs11LibraryJSON() (pkcs11LibraryJSON, error) {
	return pkcs11LibraryJSON{
		Path:      l.Path.String(),
		SlotLabel: l.SlotLabel.String(),
		SlotPin:   l.SlotPin.String(),
	}, nil
}

type EnvironmentVariable url.URL

func (e EnvironmentVariable) Get() string {
	u := url.URL(e)
	return os.Getenv(u.Host)
}

func (e EnvironmentVariable) IsSet() bool {
	u := url.URL(e)
	if u.Host == "" {
		return false
	}
	_, b := os.LookupEnv(u.Host)
	return b
}

func (e EnvironmentVariable) String() string {
	u := url.URL(e)
	return u.String()
}
