package millionaire

import (
	"crypto/rand"
	"github.com/ffddz/upside-homework/crypto/paillier"
	"math/big"
)

// Party2 구조체
type Party2 struct {
	PublicKey *paillier.PublicKey
	balance   *big.Int
}

// Party2 인스턴스 생성
func NewParty2(publicKey *paillier.PublicKey, balance *big.Int) *Party2 {
	return &Party2{
		PublicKey: publicKey,
		balance:   balance,
	}
}


func (p *Party2) generateRandomInN() *big.Int {
    sqrtN := new(big.Int).Sqrt(p.PublicKey.N) // 난수 범위를 sqrt(N)로 제한
    n, _ := rand.Int(rand.Reader, sqrtN)
    return n
}

// Party2의 Step1 구현 (모든 연산을 N^2으로 제한)
func (p *Party2) Step1(c0 *big.Int) (*big.Int, *big.Int, error) {
	N2 := new(big.Int).Mul(p.PublicKey.N, p.PublicKey.N) // N^2 계산

	b0 := p.generateRandomInN()
	b1 := p.generateRandomInN()

	C_prime, _, err := p.PublicKey.Encrypt(b0) // 난수 b0을 암호화
	if err != nil {
		return nil, nil, err
	}

	c1 := new(big.Int).Exp(c0, b1, N2) // c0^b1 (mod N^2)
	c1.Mul(c1, C_prime).Mod(c1, N2)   // c1 = (c0^b1 * C') mod N^2

	b1v1 := new(big.Int).Mul(b1, p.balance) // b1 * v1
	sum := new(big.Int).Add(b1v1, b0)       // sum = b1*v1 + b0
	sum.Mod(sum, p.PublicKey.N)             // sum (mod N)

	c2, _, err := p.PublicKey.Encrypt(sum)
	if err != nil {
		return nil, nil, err
	}

	return c1, c2, nil
}