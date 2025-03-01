package millionaire

import (
	"fmt"
	"github.com/ffddz/upside-homework/crypto/paillier"
	"math/big"
)

type Party2 struct {
	PublicKey *paillier.PublicKey
	balance   *big.Int
}

// NewParty2 create new Party2
func NewParty2(publicKey *paillier.PublicKey, balance *big.Int) *Party2 {
	return &Party2{
		PublicKey: publicKey,
		balance:   balance,
	}
}

// TODO Party2의 Step1을 구현하시오
func (p *Party2) Step1(c0 *big.Int) (c1 *big.Int, c2 *big.Int, err error) {
	return nil, nil, fmt.Errorf("not implemented")
}
