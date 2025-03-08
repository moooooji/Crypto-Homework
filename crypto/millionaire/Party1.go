package millionaire

import (
	"github.com/ffddz/upside-homework/crypto/paillier"
	"math/big"
)

type Party1 struct {
	privateKey *paillier.PrivateKey
	PublicKey  *paillier.PublicKey
	balance    *big.Int
}

func NewParty1(balance *big.Int) (*Party1, error) {
	privateKey, publicKey, err := paillier.NewKeyPair()
	if err != nil {
		return nil, err
	}

	return &Party1{
		privateKey: privateKey,
		PublicKey:  publicKey,
		balance:    balance,
	}, nil
}

func (p *Party1) Step1() (*big.Int, error) {
	c0, _, err := p.PublicKey.Encrypt(p.balance)
	return c0, err
}

func (p Party1) Step2(c1, c2 *big.Int) (int, error) {
	b1Balance, err := p.privateKey.Decrypt(c1)
	if err != nil {
		return 0, err
	}

	b2Balance, err := p.privateKey.Decrypt(c2)
	if err != nil {
		return 0, err
	}

	return b1Balance.Cmp(b2Balance), nil
}
