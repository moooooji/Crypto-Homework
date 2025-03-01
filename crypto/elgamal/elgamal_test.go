package elgamal

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestElGamal(t *testing.T) {
	// ElGamal 파라미터 설정
	p, _ := big.NewInt(0).SetString("fffffffffffffffffffffffffffffffeffffffffffffffff", 16)
	g := big.NewInt(2)
	eg := NewElGamal(p, g)

	t.Run("Basic Encryption and Decryption", func(t *testing.T) {
		message := big.NewInt(42)
		c1, c2, err := eg.Encrypt(message, eg.PK)
		assert.NoError(t, err)
		decrypted, err := eg.Decrypt(c1, c2)
		assert.NoError(t, err)

		assert.Equal(t, message, decrypted, "복호화 결과가 원본 메시지와 같아야 합니다")
	})

	t.Run("Different Sized Messages", func(t *testing.T) {
		messages := []*big.Int{
			big.NewInt(1),
			big.NewInt(123456789),
			new(big.Int).Sub(p, big.NewInt(1)),
			new(big.Int).Div(p, big.NewInt(2)),
			new(big.Int).Div(p, big.NewInt(4)),
			new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil),
		}

		for _, msg := range messages {
			c1, c2, err := eg.Encrypt(msg, eg.PK)

			if msg.Cmp(p) >= 0 {
				// 메시지가 p 이상이면 암호화가 실패해야 함
				assert.Error(t, err, "메시지가 p보다 크다면 암호화는 실패해야 합니다")
			} else {
				// 메시지가 p 미만이면 정상적으로 암호화 및 복호화가 되어야 함
				assert.NoErrorf(t, err, "암호화 실패: %v", err)
				decrypted, err := eg.Decrypt(c1, c2)
				assert.NoErrorf(t, err, "복호화 실패: %v", err)
				assert.Equal(t, msg, decrypted, "복호화 결과가 입력 메시지와 같아야 합니다")
			}
		}
	})

	t.Run("Random Messages", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			msg, _ := rand.Int(rand.Reader, p)
			c1, c2, err := eg.Encrypt(msg, eg.PK)
			assert.NoErrorf(t, err, "암호화 실패: %v", err)
			decrypted, err := eg.Decrypt(c1, c2)
			assert.NoErrorf(t, err, "복호화 실패: %v", err)

			assert.Equal(t, msg, decrypted, "랜덤 메시지 복호화 실패")
		}
	})

	t.Run("Randomness of Encryption", func(t *testing.T) {
		message := big.NewInt(100)
		c1_1, c2_1, err := eg.Encrypt(message, eg.PK)
		assert.NoError(t, err)
		c1_2, c2_2, err := eg.Encrypt(message, eg.PK)
		assert.NoError(t, err)

		assert.NotEqual(t, c1_1, c1_2, "동일한 메시지는 매번 다른 암호문을 가져야 합니다")
		assert.NotEqual(t, c2_1, c2_2, "동일한 메시지는 매번 다른 암호문을 가져야 합니다")
	})

	t.Run("Different Messages Encryption", func(t *testing.T) {
		msg1 := big.NewInt(50)
		msg2 := big.NewInt(200)

		c1_1, c2_1, err := eg.Encrypt(msg1, eg.PK)
		assert.NoError(t, err)
		c1_2, c2_2, err := eg.Encrypt(msg2, eg.PK)
		assert.NoError(t, err)

		assert.NotEqual(t, c1_1, c1_2, "서로 다른 메시지는 다른 암호문을 가져야 합니다")
		assert.NotEqual(t, c2_1, c2_2, "서로 다른 메시지는 다른 암호문을 가져야 합니다")
	})

	t.Run("Boundary Values", func(t *testing.T) {
		boundaryMessages := []*big.Int{
			big.NewInt(0),
			new(big.Int).Sub(p, big.NewInt(1)),
			new(big.Int).Div(p, big.NewInt(2)),
		}

		for _, msg := range boundaryMessages {
			c1, c2, err := eg.Encrypt(msg, eg.PK)
			assert.NoErrorf(t, err, "암호화 실패: %v", err)
			decrypted, err := eg.Decrypt(c1, c2)
			assert.NoErrorf(t, err, "복호화 실패: %v", err)

			assert.Equal(t, msg, decrypted, "경계값 복호화 실패")
		}
	})

	t.Run("Decryption Failure with Wrong Key", func(t *testing.T) {
		eg2 := NewElGamal(p, g) // 다른 키를 가진 ElGamal 객체
		message := big.NewInt(75)

		c1, c2, err := eg.Encrypt(message, eg.PK)
		assert.NoError(t, err)
		decrypted, _ := eg2.Decrypt(c1, c2)
		assert.NotEqual(t, message, decrypted, "잘못된 키로 복호화값이 다르게 나와야 합니다")
	})
}
