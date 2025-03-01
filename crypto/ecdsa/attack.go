package ecdsa

import (
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"math/big"
)

// TODO 동일한 k로 서명한 경우 private Key 추출공격을 구현하시오
func AttackGetPrivateKey(r1, s1, r2, s2 *big.Int, msg1, msg2 []byte) (*secp256k1.PrivateKey, error) {
	return nil, fmt.Errorf("not implemented")
}
