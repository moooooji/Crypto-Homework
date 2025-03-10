package ecdsa

import (
	"github.com/ffddz/upside-homework/crypto"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"math/big"
)

// 동일한 k로 서명한 경우 private Key 추출 공격
func AttackGetPrivateKey(r1, s1, r2, s2 *big.Int, msg1, msg2 []byte) (*secp256k1.PrivateKey, error) {
    if r1.Cmp(r2) != 0 {
        return nil, fmt.Errorf("r1 and r2 must be the same for this attack")
    }

    // 메시지 해시값을 정수로 변환
    h1 := crypto.HashToInt(msg1)
    h2 := crypto.HashToInt(msg2)

    // x = (s2*h1 - s1*h2) / (r * (s1 - s2))
    numerator := new(big.Int).Sub(new(big.Int).Mul(s2, h1), new(big.Int).Mul(s1, h2))
    denominator := new(big.Int).Mul(r1, new(big.Int).Sub(s1, s2))

    // modular inverse
    denominatorInv := new(big.Int).ModInverse(denominator, secp256k1.S256().N)
    if denominatorInv == nil {
        return nil, fmt.Errorf("unable to compute modular inverse")
    }

    pkInt := new(big.Int).Mul(numerator, denominatorInv)
    pkInt.Mod(pkInt, secp256k1.S256().N) // 모듈러 연산

    // 올바른 키 생성
    privateKey := secp256k1.PrivKeyFromBytes(pkInt.Bytes())

    return privateKey, nil
}