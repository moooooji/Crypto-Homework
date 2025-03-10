package ecdsa

import (
	"crypto/ecdsa"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"testing"
	"fmt"
)

func TestAttackGetPrivateKey(t *testing.T) {
	t.Run("ECDSA 동일한 k로 서명한 경우 Private Key추출 공격", func(t *testing.T) {
		// private key 생성
		privateKey, err := secp256k1.GeneratePrivateKey()
		assert.NoError(t, err)

		fmt.Println("1. Recovered Private Key: ", privateKey)

		// 서명 생성
		msg1 := []byte("hello, world!")
		r1, s1, err := Sign(privateKey, msg1)
		assert.NoError(t, err)

		// 서명 생성
		msg2 := []byte("hello, upside!")
		r2, s2, err := Sign(privateKey, msg2)
		assert.NoError(t, err)

		assert.Equal(t, true, ecdsa.Verify(privateKey.PubKey().ToECDSA(), msg1, r1, s1))
		assert.Equal(t, true, ecdsa.Verify(privateKey.PubKey().ToECDSA(), msg2, r2, s2))

		// 공격
		attackedPrivateKey, err := AttackGetPrivateKey(r1, s1, r2, s2, msg1, msg2)
		assert.NoError(t, err)

		// 공격 성공 확인
		assert.Equal(t, privateKey, attackedPrivateKey)
	})
}
