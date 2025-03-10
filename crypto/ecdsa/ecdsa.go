package ecdsa

import (
	"errors"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ffddz/upside-homework/crypto"
	"math/big"
	"fmt"
)

var (
	order     = new(big.Int).Set(secp256k1.S256().N)
	halforder = new(big.Int).Rsh(order, 1)
	// 안전하지 않게 k를 동일한 것을 사용
	k = new(big.Int).SetUint64(0x123456789abcdef)
)

func Sign(privateKey *secp256k1.PrivateKey, hash []byte) (*big.Int, *big.Int, error) {
	privkey := privateKey.ToECDSA()
	fmt.Println("3. Recovered Private Key: ", privkey)
	N := order
	inv := new(big.Int).ModInverse(k, N)
	r, _ := privkey.Curve.ScalarBaseMult(k.Bytes())
	r.Mod(r, N)

	if r.Sign() == 0 {
		return nil, nil, errors.New("calculated R is zero")
	}

	e := crypto.HashToInt(hash)
	s := new(big.Int).Mul(privkey.D, r)
	s.Add(s, e)
	s.Mul(s, inv)
	s.Mod(s, N)

	// enforce low S values, see bip62
	// bip62을 반영하지 않은 ECDSA 서명을 만들기 위해 주석처리
	//if s.Cmp(halforder) == 1 {
	//	s.Sub(N, s)
	//}

	if s.Sign() == 0 {
		return nil, nil, errors.New("calculated S is zero")
	}
	return r, s, nil
}
