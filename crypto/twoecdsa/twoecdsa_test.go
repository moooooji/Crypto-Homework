package twoecdsa

import (
	"crypto/ecdsa"
	"github.com/ffddz/upside-homework/crypto"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestSign(t *testing.T) {
	party2 := NewParty2()
	party1 := NewParty1()

	aG := party1.KeyGenStep1()
	bG := party2.KeyGenStep1()

	party1.KeyGenStep2(bG)
	party2.KeyGenStep2(aG)
	assert.Equal(t, party1.PubKey, party2.PubKey)

	k1G := party1.SignStep1()
	k2G := party2.SignStep1()

	// p_{\text{521}}= 2^{521} - 1
	p := new(big.Int).Sub(big.NewInt(1).Lsh(big.NewInt(1), 521), big.NewInt(1))
	g := big.NewInt(2)
	rho := 256

	otAList, err := party2.SignStep2(k1G, p, g, curve.N, rho)
	assert.NoError(t, err)

	otBList := party1.SignStep2(k2G, p, g, curve.N, rho, otAList)

	msg := []byte("hello, upside!")
	h := crypto.HashToInt(msg)

	c0List, c1List, nonceK0List, nonceK1List, err := party2.SignStep3(otBList)
	assert.NoError(t, err)

	z, err := party1.SignStep3(c0List, c1List, nonceK0List, nonceK1List)
	assert.NoError(t, err)

	s2, err := party2.SignStep4(z, h)
	assert.NoError(t, err)
	r, s, err := party1.SignStep4(s2)
	assert.NoError(t, err)

	assert.Equal(t, true, ecdsa.Verify(party1.PubKey.ToECDSA(), msg, r, s))
}
