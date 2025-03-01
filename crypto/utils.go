package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"io"
	"math/big"
)

var (
	one = big.NewInt(1)
)

// RandomNum generates a random number r, 1 < r < n.
// Input n has to be greater than 1, otherwise panic
func RandomNum(n *big.Int) *big.Int {
	if n == nil {
		panic(fmt.Errorf("RandomNum error, n is nil"))
	}
	if n.Cmp(one) != 1 {
		panic(fmt.Errorf("RandomNum error: max has to be greater than 1"))
	}
	for {
		r, err := rand.Int(rand.Reader, n)
		if err != nil {
			panic(fmt.Errorf("RandomNum error"))
		}
		if r.Cmp(one) == 1 {
			return r
		}
	}
}

// RandomPrimeNum  `r < n` and `gcd(r,n) = 1`
func RandomPrimeNum(n *big.Int) (*big.Int, error) {
	if n.Cmp(one) != 1 {
		return nil, fmt.Errorf("RandomPrimeNum error: max has to be greater than 1")
	}
	gcd := new(big.Int)
	r := new(big.Int)
	var err error
	for gcd.Cmp(one) != 0 {
		r, err = rand.Int(rand.Reader, n)
		if err != nil {
			return nil, err
		}
		gcd = new(big.Int).GCD(nil, nil, r, n)
	}
	return r, nil
}

// GenerateSafePrime generates a prime number `p`; a prime 'p' such that 2p+1 is also prime.
func GenerateSafePrime(bits int, values chan *big.Int, quit chan int) (p *big.Int, err error) {
	for {
		select {
		case <-quit:
			return
		default:
			// this is to make it non-blocking
		}
		p, err = rand.Prime(rand.Reader, bits-1)
		if err != nil {
			return nil, err
		}
		// 2p+1
		p = new(big.Int).Lsh(p, 1)
		p = new(big.Int).Add(p, one)
		if p.ProbablyPrime(20) {
			select {
			case <-quit:
				return
			default:
				// this is to make it non-blocking
			}
			values <- p
			return
		}
	}
}

func HashToInt(hash []byte) *big.Int {
	orderBits := secp256k1.S256().Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

// EncryptBigInt는 키(key)와 big.Int 객체를 받아 AES-GCM으로 암호화한 후,
// (nonce, ciphertext)를 반환합니다.
func EncryptBigInt(key []byte, input *big.Int) (nonce, ciphertext []byte, err error) {
	// 1. AES 블록 생성
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// 2. GCM 생성
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	// 3. Nonce(IV) 생성
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	// 4. big.Int -> []byte 변환
	plaintext := input.Bytes()

	// 5. AES-GCM 암호화
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

// DecryptBigInt는 키(key)와 함께 nonce, ciphertext를 받아 AES-GCM 복호화한 후,
// 원래의 big.Int 객체로 복원합니다.
func DecryptBigInt(key, nonce, ciphertext []byte) (*big.Int, error) {
	// 1. AES 블록 생성
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 2. GCM 생성
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 3. 복호화
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	// 4. []byte -> big.Int 변환
	var result big.Int
	result.SetBytes(plaintext)
	return &result, nil
}

// HashBigInt는 big.Int 값을 받아 SHA-256으로 해싱한 결과를 반환합니다.
func HashBigInt(input *big.Int) []byte {
	// big.Int → []byte 변환 후 sha256 해시
	r := sha256.Sum256(input.Bytes())
	return r[:]
}
