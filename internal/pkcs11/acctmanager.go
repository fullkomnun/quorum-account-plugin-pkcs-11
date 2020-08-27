package pkcs11

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log"
	"quorum-account-plugin-pkcs-11/internal/account/account"
	"quorum-account-plugin-pkcs-11/internal/config"
	"strings"
	"sync"
	"time"
)

func NewAccountManager(wrapper Cryptoki, config config.Config) (AccountManager, error) {
	if wrapper == nil {
		panic("")
	}

	a := &accountManager{
		wrapper:  wrapper,
		unlocked: make(map[string]*lockableKey),
	}

	for _, toUnlock := range config.Unlock {
		addr, err := account.NewAddressFromHexString(toUnlock)
		if err != nil {
			log.Printf("[INFO] unable to unlock %v, err = %v", toUnlock, err)
		}
		if err := a.TimedUnlock(addr, 0); err != nil {
			log.Printf("[INFO] unable to unlock %v, err = %v", toUnlock, err)
		}
	}

	return a, nil
}

type AccountManager interface {
	Open() error
	Close() error
	Status() (string, error)
	Accounts() ([]account.Account, error)
	Contains(acctAddr account.Address) bool
	Sign(acctAddr account.Address, toSign []byte) ([]byte, error)
	UnlockAndSign(acctAddr account.Address, toSign []byte) ([]byte, error)
	TimedUnlock(acctAddr account.Address, duration time.Duration) error
	Lock(acctAddr account.Address)
	NewAccount(conf config.NewAccount) (account.Account, error)
	ImportPrivateKey(privateKeyECDSA *ecdsa.PrivateKey, conf config.NewAccount) (account.Account, error)
}

type accountManager struct {
	wrapper  Cryptoki
	unlocked map[string]*lockableKey
	mu       sync.Mutex
}

type lockableKey struct {
	cancel chan struct{}
}

func (a *accountManager) Open() error {
	return a.wrapper.OpenSession()
}

func (a *accountManager) Close() error {
	return a.wrapper.CloseSession()
}

func (a *accountManager) Status() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	unlockedCount := len(a.unlocked)

	status := fmt.Sprintf("%v unlocked account(s)", unlockedCount)
	if unlockedCount != 0 {
		var unlockedAddrs []string
		for addr, _ := range a.unlocked {
			unlockedAddrs = append(unlockedAddrs, fmt.Sprintf("0x%v", addr))
		}
		status = fmt.Sprintf("%v: %v", status, unlockedAddrs)
	}

	return status, nil
}

func (a *accountManager) Accounts() ([]account.Account, error) {
	return a.wrapper.Accounts()
}

func (a *accountManager) Contains(acctAddr account.Address) bool {
	return a.wrapper.Contains(acctAddr)
}

func (a *accountManager) Sign(acctAddr account.Address, toSign []byte) ([]byte, error) {
	if !a.Contains(acctAddr) {
		return nil, errors.New("account does not exist")
	}
	a.mu.Lock()
	_, ok := a.unlocked[acctAddr.ToHexString()]
	a.mu.Unlock()
	if !ok {
		return nil, errors.New("account locked")
	}
	return a.wrapper.Sign(toSign, acctAddr)
}

func (a *accountManager) UnlockAndSign(acctAddr account.Address, toSign []byte) ([]byte, error) {
	if !a.Contains(acctAddr) {
		return nil, errors.New("account does not exist")
	}
	a.mu.Lock()
	_, unlocked := a.unlocked[acctAddr.ToHexString()]
	a.mu.Unlock()
	if !unlocked {
		if err := a.TimedUnlock(acctAddr, 0); err != nil {
			return nil, err
		}
		defer a.Lock(acctAddr)
		_, _ = a.unlocked[acctAddr.ToHexString()]
	}
	return a.wrapper.Sign(toSign, acctAddr)
}

func (a *accountManager) TimedUnlock(acctAddr account.Address, duration time.Duration) error {
	if !a.Contains(acctAddr) {
		return errors.New("account does not exist")
	}

	lockableKey := &lockableKey{
		//key: key,
	}

	if duration > 0 {
		go a.lockAfter(acctAddr.ToHexString(), lockableKey, duration)
	}

	a.mu.Lock()
	addr := strings.TrimPrefix(acctAddr.ToHexString(), "0x")
	a.unlocked[addr] = lockableKey
	a.mu.Unlock()

	return nil
}

func (a *accountManager) lockAfter(addr string, key *lockableKey, duration time.Duration) {
	t := time.NewTimer(duration)
	defer t.Stop()

	select {
	case <-key.cancel:
		// cancel the scheduled lock
	case <-t.C:
		if a.unlocked[addr] == key {
			a.mu.Lock()
			delete(a.unlocked, addr)
			a.mu.Unlock()
		}
	}
}

func (a *accountManager) Lock(acctAddr account.Address) {
	addrHex := acctAddr.ToHexString()
	a.mu.Lock()
	lockable, ok := a.unlocked[addrHex]
	a.mu.Unlock()

	if ok {
		a.lockAfter(addrHex, lockable, 0)
	}
}

func (a *accountManager) NewAccount(conf config.NewAccount) (account.Account, error) {
	return a.wrapper.NewAccount(conf)
}

func (a *accountManager) ImportPrivateKey(privateKeyECDSA *ecdsa.PrivateKey, conf config.NewAccount) (account.Account, error) {
	return a.wrapper.ImportPrivateKey(privateKeyECDSA, conf)
}
