package mta

import (
	"fmt"
	"github.com/ffddz/upside-homework/crypto"
	"math/big"
)

// Alice MtA 프로토콜에서의 Alice, 1 out of 2 OT의 Receiver
type Alice struct {
	a        *big.Int   // 비밀 값 a
	p        *big.Int   // ElGamal 소수
	g        *big.Int   // ElGamal 생성자
	modulus  *big.Int   // 계산 모듈러스
	rho      int        // 비트 길이
	otKrList []*big.Int // OT 복호화 키
}

// NewAlice 새로운 Alice 인스턴스를 생성
func NewAlice(a, p, g, modulus *big.Int, rho int) *Alice {
	return &Alice{a: a, p: p, g: g, modulus: modulus, rho: rho, otKrList: make([]*big.Int, 0)}
}

// Step1 Alice가 OT를 위해 공개 키를 생성하여 반환
func (alice *Alice) Step1(otAList []*big.Int) []*big.Int {
	aBits := make([]int, alice.rho)

	// Alice의 비밀 값 `a`를 비트 단위로 분할
	for i := 0; i < alice.rho; i++ {
		aBits[i] = int(alice.a.Bit(i))
	}

	// aBits에 따라 a_i == 0 이면 B = g^b_i, a_i == 1 이면 B = g^b_i * A_i
	otBList := make([]*big.Int, alice.rho)
	for i := 0; i < alice.rho; i++ {
		ot_b := crypto.RandomNum(alice.p)

		if aBits[i] == 0 {
			otB := new(big.Int).Exp(alice.g, ot_b, alice.p)
			otBList[i] = otB
		} else {
			otB := new(big.Int).Mul(new(big.Int).Exp(alice.g, ot_b, alice.p), otAList[i])
			otB.Mod(otB, alice.p)
			otBList[i] = otB
		}

		// 복호화키 저장
		kr := new(big.Int).Exp(otAList[i], ot_b, alice.p)
		alice.otKrList = append(alice.otKrList, kr)
	}

	return otBList
}

// TODO Step2 Bob으로부터 암호화된 메시지를 받아 a의 비트에 따라 복호화하고 x를 계산
func (alice *Alice) Step2(c0List, c1List, nonceK0List, nonceK1List [][]byte) (*big.Int, error) {
	return nil, fmt.Errorf("not implemented")
}
