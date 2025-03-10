package ecdsa

import (
	"crypto/sha256"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"math/big"
)

// HashToInt는 메시지 해시를 big.Int로 변환
func HashToInt(msg []byte) *big.Int {
	hash := sha256.Sum256(msg)
	return new(big.Int).SetBytes(hash[:])
}

// 동일한 k로 서명한 경우 private Key 추출 공격
func AttackGetPrivateKey(r1, s1, r2, s2 *big.Int, msg1, msg2 []byte) (*secp256k1.PrivateKey, error) {
	if r1.Cmp(r2) != 0 {
		return nil, fmt.Errorf("r1 and r2 must be the same for this attack")
	}

	// 해시 값 변환
	h1 := HashToInt(msg1)
	h2 := HashToInt(msg2)

	// x = (s2*h1 - s1*h2) / (r * (s1 - s2))
	a := new(big.Int).Sub(new(big.Int).Mul(s2, h1), new(big.Int).Mul(s1, h2))
	b := new(big.Int).Mul(r1, new(big.Int).Sub(s1, s2))

	// modular inverse
	c := new(big.Int).ModInverse(b, secp256k1.S256().N)
	if denominatorInv == nil {
		return nil, fmt.Errorf("unable to compute modular inverse")
	}

	pkInt := new(big.Int).Mul(a, c)
	pkInt.Mod(privateKeyInt, secp256k1.S256().N) // 최종 값 모듈러 연산

	pk, _ := secp256k1.PrivKeyFromBytes(pkInt.Bytes())

	return privateKey, nil
}