package paillier

import (
	"github.com/stretchr/testify/assert"
	"math/big"
	"runtime"
	"testing"
)

func TestPaillier(t *testing.T) {
	t.Run("Paillier 암복호화, 동형덧셈, 동형곱셈 테스트", func(t *testing.T) {
		privateKey, publicKey, err := NewKeyPair(runtime.NumCPU())
		assert.NoError(t, err)

		num1 := big.NewInt(10)
		num2 := big.NewInt(32)
		c1, _, err := publicKey.Encrypt(num1)
		assert.NoError(t, err)

		c2, _, err := publicKey.Encrypt(num2)
		assert.NoError(t, err)
		c3, err := publicKey.HomoAdd(c1, c2)
		assert.NoError(t, err)

		ciphered, err := publicKey.HomoMulPlain(c3, num1)
		assert.NoError(t, err)

		plain, err := privateKey.Decrypt(ciphered)
		assert.NoError(t, err)
		assert.Equal(t, new(big.Int).Mul(new(big.Int).Add(num1, num2), num1), plain)
	})
}
