package account

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/jpmorganchase/quorum/crypto/secp256k1"
	"github.com/stretchr/testify/require"
)

func TestNewKeyFromHexString(t *testing.T) {
	var (
		hexKey  = "1fe8f1ad4053326db20529257ac9401f2e6c769ef1d736b8c2f5aba5f787c72b"
		want, _ = hex.DecodeString(hexKey)
		got     *ecdsa.PrivateKey
		err     error
	)

	got, err = NewKeyFromHexString("1fe8f1ad4053326db20529257ac9401f2e6c769ef1d736b8c2f5aba5f787c72b")
	require.NoError(t, err)
	require.Equal(t, want, got.D.Bytes())

	got, err = NewKeyFromHexString("0x1fe8f1ad4053326db20529257ac9401f2e6c769ef1d736b8c2f5aba5f787c72b")
	require.NoError(t, err)
	require.Equal(t, want, got.D.Bytes())
}

func TestNewKeyFromHexString_InvalidHex(t *testing.T) {
	_, err := NewKeyFromHexString("this-is-not-hex")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid hex private key")
}

func TestNewKeyFromHexString_TooShort(t *testing.T) {
	_, err := NewKeyFromHexString("1fe8")
	require.EqualError(t, err, "private key must have length 32 bytes")
}

func TestPublicKeyBytesToAddress(t *testing.T) {
	byt, _ := hex.DecodeString("1fe8f1ad4053326db20529257ac9401f2e6c769ef1d736b8c2f5aba5f787c72b")
	key := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: secp256k1.S256(),
		},
		D: new(big.Int).SetBytes(byt),
	}
	key.X, key.Y = key.Curve.ScalarBaseMult(byt)
	pubBytes := elliptic.Marshal(secp256k1.S256(), key.PublicKey.X, key.PublicKey.Y)

	addrByt, _ := hex.DecodeString("6038dc01869425004ca0b8370f6c81cf464213b3")
	var want Address
	copy(want[:], addrByt)

	got, err := PublicKeyBytesToAddress(pubBytes)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestPublicKeyToAddress_InvalidKey(t *testing.T) {
	var (
		key    *ecdsa.PublicKey
		gotErr error
		want   = "invalid key: unable to derive address"
	)

	key = nil
	_, gotErr = PublicKeyToAddress(key)
	require.EqualError(t, gotErr, want)

	key = new(ecdsa.PublicKey)
	key.X = big.NewInt(1)
	_, gotErr = PublicKeyToAddress(key)
	require.EqualError(t, gotErr, want)

	key = new(ecdsa.PublicKey)
	key.Y = big.NewInt(1)
	_, gotErr = PublicKeyToAddress(key)
	require.EqualError(t, gotErr, want)
}
