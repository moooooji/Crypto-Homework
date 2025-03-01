package mta

import (
	"github.com/ffddz/upside-homework/crypto"
	"math/big"
)

// Bob MtA 프로토콜에서의 Bob, 1 out of 2 OT의 Sender
type Bob struct {
	b       *big.Int   // 비밀 값 b
	p       *big.Int   // ElGamal 소수
	g       *big.Int   // ElGamal 생성자
	modulus *big.Int   // 계산 모듈러스
	rho     int        // 비트 길이
	otaList []*big.Int // 1 out of 2 OT에서 Sender의 a 값 리스트 (rho 개)
	otAList []*big.Int // 1 out of 2 OT에서 Sender의 A 값 리스트 (rho 개)
}

// NewBob 새로운 Bob 인스턴스를 생성
func NewBob(b, p, g, modulus *big.Int, rho int) *Bob {
	return &Bob{b: b, p: p, g: g, modulus: modulus, rho: rho, otaList: make([]*big.Int, rho), otAList: make([]*big.Int, rho)}
}

// Step1 1 out of 2 OT를 위해 A= g^a 를 rho 개 생성하여 반환
func (bob *Bob) Step1() []*big.Int {
	for i := 0; i < bob.rho; i++ {
		a := crypto.RandomNum(bob.p)
		A := new(big.Int).Exp(bob.g, a, bob.p)
		bob.otaList[i] = a
		bob.otAList[i] = A
	}
	return bob.otAList
}

// Step2 Alice의 공개 키를 받아 암호화된 메시지를 생성하고 y 값을 계산하여 반환
func (bob *Bob) Step2(otBList []*big.Int) ([][]byte, [][]byte, [][]byte, [][]byte, *big.Int, error) {
	otK0List := make([]*big.Int, bob.rho)
	otK1List := make([]*big.Int, bob.rho)

	for i := 0; i < bob.rho; i++ {
		// k0 = B^ota
		k0 := new(big.Int).Exp(otBList[i], bob.otaList[i], bob.p)
		// k1 = (B/A)^ota
		otAInverse := new(big.Int).ModInverse(bob.otAList[i], bob.p)
		k1 := new(big.Int).Mul(otBList[i], otAInverse)
		k1.Exp(k1, bob.otaList[i], bob.p)
		otK0List[i] = k0
		otK1List[i] = k1
	}

	// s_i, t_i^0, t_i^1 준비
	s := make([]*big.Int, bob.rho)
	t0 := make([]*big.Int, bob.rho)
	t1 := make([]*big.Int, bob.rho)

	for i := 0; i < bob.rho; i++ {
		s[i] = crypto.RandomNum(bob.p)
		t0[i] = s[i]
		twoI := new(big.Int).Lsh(big.NewInt(1), uint(i))
		t1[i] = new(big.Int).Add(new(big.Int).Mul(twoI, bob.b), s[i])
		t1[i] = new(big.Int).Mod(t1[i], bob.p)
	}

	// t0[i], t1[i]를 Alice의 공개 키로 암호화
	c0List := make([][]byte, bob.rho)
	c1List := make([][]byte, bob.rho)
	nonceK0List := make([][]byte, bob.rho)
	nonceK1List := make([][]byte, bob.rho)
	for i := 0; i < bob.rho; i++ {
		k0 := crypto.HashBigInt(otK0List[i])
		nonceK0, c0, err := crypto.EncryptBigInt(k0, t0[i])
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

		k1 := crypto.HashBigInt(otK1List[i])
		nonceK1, c1, err := crypto.EncryptBigInt(k1, t1[i])
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

		nonceK0List[i] = nonceK0
		nonceK1List[i] = nonceK1

		c0List[i] = c0
		c1List[i] = c1
	}

	// y = -sum s_i 계산
	y := big.NewInt(0)
	for i := 0; i < bob.rho; i++ {
		y.Sub(y, s[i])
		y.Mod(y, bob.modulus)
	}

	// 직렬화된 암호문과 y 반환
	return c0List, c1List, nonceK0List, nonceK1List, y, nil
}
