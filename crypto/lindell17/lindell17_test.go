package lindell17

import (
	"crypto/ecdsa"
	"github.com/ffddz/upside-homework/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSign(t *testing.T) {
	party2 := NewParty2()
	party1 := NewParty1()

	aG := party1.KeyGenStep1()
	bG := party2.KeyGenStep1()

	party1.KeyGenStep2(bG)
	beta, ek, err := party2.KeyGenStep2(aG)
	assert.NoError(t, err)
	assert.Equal(t, party1.PubKey, party2.PubKey)

	party1.KeyGenStep3(ek, beta)

	k1G := party1.SignStep1()
	k2G := party2.SignStep1()

	party1.SignStep2(k2G)
	party2.SignStep2(k1G)

	msg := []byte("hello, upside!")
	h := crypto.HashToInt(msg)

	c, err := party1.SignStep3(h)
	assert.NoError(t, err)

	s, r, err := party2.SignStep3(c, msg)
	assert.NoError(t, err)
	assert.Equal(t, true, ecdsa.Verify(party1.PubKey.ToECDSA(), msg, r, s))
}
