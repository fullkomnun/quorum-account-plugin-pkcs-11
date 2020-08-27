package pkcs11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/miekg/pkcs11"
	"os"
	"quorum-account-plugin-pkcs-11/internal/account/account"
	"quorum-account-plugin-pkcs-11/internal/config"
	"runtime"
)

func NewCryptoki(config config.Pkcs11Library) (Cryptoki, error) {
	if _, err := os.Stat(config.Path.Path); os.IsNotExist(err) {
		return nil, err
	}

	ctx := pkcs11.New(config.Path.Path)
	err := ctx.Initialize()
	if err != nil {
		return nil, err
	}

	p := &pkcs11Wrapper{
		Library: config,
		Context: ctx,
	}
	runtime.SetFinalizer(p, func(a *pkcs11Wrapper) {
		p.Context.Finalize()
		p.Context.Destroy()
	})

	return p, nil
}

type Cryptoki interface {
	OpenSession() error
	CloseSession() error
	Accounts() ([]account.Account, error)
	Contains(acctAddr account.Address) bool
	Sign(toSign []byte, acctAddr account.Address) ([]byte, error)
	NewAccount(conf config.NewAccount) (account.Account, error)
	ImportPrivateKey(privateKeyECDSA *ecdsa.PrivateKey, conf config.NewAccount) (account.Account, error)
}

type pkcs11Wrapper struct {
	Library config.Pkcs11Library
	Context *pkcs11.Ctx
	Session pkcs11.SessionHandle
}

func (p *pkcs11Wrapper) OpenSession() error {
	slots, err := p.Context.GetSlotList(true)
	if err != nil {
		return err
	}

	for _, s := range slots {
		info, err := p.Context.GetTokenInfo(s)
		if err != nil || p.Library.SlotLabel.Get() != info.Label {
			continue
		}

		p.Session, err = p.Context.OpenSession(s, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			return err
		}
	}

	var slotPIN = ""
	if p.Library.SlotPin.IsSet() {
		slotPIN = p.Library.SlotPin.Get()
	}
	err = p.Context.Login(p.Session, pkcs11.CKU_USER, slotPIN)
	if err != nil {
		return err
	}
	return nil
}

func (p *pkcs11Wrapper) CloseSession() error {
	err := p.Context.Logout(p.Session)
	if err != nil {
		return err
	}
	err = p.Context.CloseSession(p.Session)
	if err != nil {
		return err
	}
	return nil
}

func (p *pkcs11Wrapper) Accounts() ([]account.Account, error) {
	var (
		w, _  = p.findAllKeys()
		accts = make([]account.Account, 0, len(w))
		acct  account.Account
	)
	for _, acctHandle := range w {
		idTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		}
		addrAttr, err := p.Context.GetAttributeValue(p.Session, acctHandle, idTemplate)
		if err != nil {
			return []account.Account{}, err
		}
		addr, err := account.NewAddress(addrAttr[0].Value)
		if err != nil {
			return []account.Account{}, err
		}
		acct = account.Account{
			Address: addr,
			URL:     nil,
		}
		accts = append(accts, acct)
	}
	return accts, nil
}

func (p *pkcs11Wrapper) findAllKeys() ([]pkcs11.ObjectHandle, error) {
	findTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	}
	err := p.Context.FindObjectsInit(p.Session, findTemplate)
	if err != nil {
		return nil, err
	}
	defer p.Context.FindObjectsFinal(p.Session)
	keys, _, err := p.Context.FindObjects(p.Session, 100)
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func (p *pkcs11Wrapper) Contains(acctAddr account.Address) bool {
	_, err := p.findPrivateKey(acctAddr)
	return err != nil
}

func (p *pkcs11Wrapper) NewAccount(conf config.NewAccount) (account.Account, error) {
	marshaledOID, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 10}) // secp256k1 oid
	if err != nil {
		return account.Account{}, err
	}

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, false),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, marshaledOID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, conf.SecretName),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, conf.SecretName),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
	}
	pubK, privK, err := p.Context.GenerateKeyPair(p.Session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		publicKeyTemplate,
		privateKeyTemplate)
	if err != nil {
		return account.Account{}, err
	}

	attr, err := p.Context.GetAttributeValue(p.Session, pubK, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_KEY_INFO, nil)})
	if err != nil {
		return account.Account{}, err
	}
	pubRaw := attr[0].Value
	addr, err := account.PublicKeyBytesToAddress(pubRaw)
	if err != nil {
		return account.Account{}, err
	}

	keyPairIdUpdateTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, addr.ToHexString()),
	}
	err = p.Context.SetAttributeValue(p.Session, pubK, keyPairIdUpdateTemplate)
	if err != nil {
		return account.Account{}, err
	}
	err = p.Context.SetAttributeValue(p.Session, privK, keyPairIdUpdateTemplate)
	if err != nil {
		return account.Account{}, err
	}

	return account.Account{Address: addr}, nil
}

func (p *pkcs11Wrapper) ImportPrivateKey(key *ecdsa.PrivateKey, conf config.NewAccount) (account.Account, error) {
	defer zeroKey(key)

	marshaledOID, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 10}) // secp256k1 oid
	if err != nil {
		return account.Account{}, err
	}

	// pubkey import
	ecPt := elliptic.Marshal(key.PublicKey.Curve, key.PublicKey.X, key.PublicKey.Y)
	// Add DER encoding for the CKA_EC_POINT
	ecPt = append([]byte{0x04, byte(len(ecPt))}, ecPt...)

	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, marshaledOID),

		pkcs11.NewAttribute(pkcs11.CKA_LABEL, conf.SecretName),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecPt),
	}

	pubK, err := p.Context.CreateObject(p.Session, keyTemplate)
	if err != nil {
		return account.Account{}, err
	} else {
		fmt.Printf("Object was imported with CKA_LABEL:%s", conf.SecretName)
	}

	keyTemplate = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, marshaledOID),

		pkcs11.NewAttribute(pkcs11.CKA_LABEL, conf.SecretName),
		pkcs11.NewAttribute(pkcs11.CKR_ATTRIBUTE_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, key.D.Bytes()),
	}

	privK, err := p.Context.CreateObject(p.Session, keyTemplate)
	if err != nil {
		return account.Account{}, err
	} else {
		fmt.Printf("Object was imported with CKA_LABEL:%s", conf.SecretName)
	}

	attr, err := p.Context.GetAttributeValue(p.Session, pubK, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_KEY_INFO, nil)})
	if err != nil {
		return account.Account{}, err
	}
	pubRaw := attr[0].Value
	addr, err := account.PublicKeyBytesToAddress(pubRaw)
	if err != nil {
		return account.Account{}, err
	}

	keyPairIdUpdateTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, addr.ToHexString()),
	}
	err = p.Context.SetAttributeValue(p.Session, pubK, keyPairIdUpdateTemplate)
	if err != nil {
		return account.Account{}, err
	}
	err = p.Context.SetAttributeValue(p.Session, privK, keyPairIdUpdateTemplate)
	if err != nil {
		return account.Account{}, err
	}

	return account.Account{Address: addr}, nil
}

func (p *pkcs11Wrapper) Sign(toSign []byte, acctAddr account.Address) ([]byte, error) {
	key, err := p.findPrivateKey(acctAddr)
	if err != nil {
		return nil, err
	}

	err = p.Context.SignInit(p.Session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA_SHA256, nil)}, key)
	if err != nil {
		return nil, err
	}

	return p.Context.Sign(p.Session, toSign)
}

func (p *pkcs11Wrapper) findPrivateKey(acctAddr account.Address) (pkcs11.ObjectHandle, error) {
	findTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, acctAddr.ToHexString()),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}
	err := p.Context.FindObjectsInit(p.Session, findTemplate)
	if err != nil {
		return 0, err
	}
	defer p.Context.FindObjectsFinal(p.Session)
	keys, _, err := p.Context.FindObjects(p.Session, 1)
	if err != nil {
		return 0, err
	} else if len(keys) == 0 {
		return 0, errors.New("key not found")
	}
	return keys[0], nil
}

func zeroKey(key *ecdsa.PrivateKey) {
	b := key.D.Bits()
	for i := range b {
		b[i] = 0
	}
}

func zero(byt []byte) {
	for i := range byt {
		byt[i] = 0
	}
}
