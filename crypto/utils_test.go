package crypto

import (
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestEncryptDecryptBigInt(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	bigInt := new(big.Int).SetInt64(1234567890)
	nonce, enc, err := EncryptBigInt(key, bigInt)
	assert.NoError(t, err)

	dec, err := DecryptBigInt(key, nonce, enc)
	assert.NoError(t, err)

	assert.Equal(t, bigInt, dec)
}
