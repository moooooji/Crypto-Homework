package elgamal

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// ElGamal ElGamal 암호화를 위한 구조체 정의
type ElGamal struct {
	p  *big.Int // 소수 모듈러스
	g  *big.Int // 생성자
	x  *big.Int // 개인 키
	PK *big.Int // 공개 키 PK = g^x mod p
}

// NewElGamal 새로운 ElGamal 인스턴스를 생성
func NewElGamal(p, g *big.Int) *ElGamal {
	eg := &ElGamal{p: p, g: g}
	eg.x, _ = rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(1))) // x ∈ [1, p-1]
	if eg.x.Cmp(big.NewInt(0)) == 0 {
		eg.x.Add(eg.x, big.NewInt(1)) // 1 이상이 되도록 조정
	}

	eg.PK = new(big.Int).Exp(g, eg.x, p)
	return eg
}

// Encrypt 공개 키 pk를 사용하여 메시지 m을 암호화
func (eg *ElGamal) Encrypt(m, pk *big.Int) (*big.Int, *big.Int, error) {
	// 메시지가 p보다 크면 암호화 불가
	if m.Cmp(eg.p) >= 0 {
		return nil, nil, errors.New("메시지가 p보다 클 수 없습니다")
	}

	k, _ := rand.Int(rand.Reader, new(big.Int).Sub(eg.p, big.NewInt(1))) // k ∈ [1, p-1]
	if k.Cmp(big.NewInt(0)) == 0 {
		k.Add(k, big.NewInt(1)) // 1 이상 보장
	}
	c1 := new(big.Int).Exp(eg.g, k, eg.p)
	s := new(big.Int).Exp(pk, k, eg.p)
	c2 := new(big.Int).Mul(m, s)
	c2.Mod(c2, eg.p)
	return c1, c2, nil
}

// TODO Decrypt 개인 키를 사용하여 암호문 (c1, c2)을 복호화
func (eg *ElGamal) Decrypt(c1, c2 *big.Int) (*big.Int, error) {
	return nil, fmt.Errorf("not implemented")
}
