package millionaire

import (
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestMillionaire(t *testing.T) {

	tc := []struct {
		name          string
		party1Balance *big.Int
		party2Balance *big.Int
		expected      int
	}{
		{
			name:          "백만장자 문제 - party1이 123456789원, party2가 123456789원을 가지고 있을 때",
			party1Balance: big.NewInt(123456789),
			party2Balance: big.NewInt(123456789),
			expected:      0,
		},
		{
			name:          "백만장자 문제 - party1이 123456788원, party2가 123456789원을 가지고 있을 때",
			party1Balance: big.NewInt(123456788),
			party2Balance: big.NewInt(123456789),
			expected:      -1,
		},
		{
			name:          "백만장자 문제 - party1이 123456789원, party2가 123456788원을 가지고 있을 때",
			party1Balance: big.NewInt(123456789),
			party2Balance: big.NewInt(12345678),
			expected:      1,
		},
	}

	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			party1, err := NewParty1(c.party1Balance)
			assert.NoError(t, err)

			party2 := NewParty2(party1.PublicKey, c.party2Balance)
			assert.NoError(t, err)

			c0, err := party1.Step1()
			assert.NoError(t, err)

			c1, c2, err := party2.Step1(c0)
			assert.NoError(t, err)

			c3, err := party1.Step2(c1, c2)
			assert.NoError(t, err)

			assert.Equal(t, c.expected, c3)
		})
	}
}
