package lindell17

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ffddz/upside-homework/crypto"
	"github.com/ffddz/upside-homework/crypto/paillier"
	"math/big"
	"runtime"
)

// Bob
type Party2 struct {
	dk     *paillier.PrivateKey
	ek     *paillier.PublicKey
	b      *big.Int
	k2     *big.Int
	r      *EcPoint
	PubKey *secp256k1.PublicKey
}

// Bob
func NewParty2() *Party2 {
	b := crypto.RandomNum(curve.N)

	return &Party2{
		b: b,
	}
}

func (p *Party2) KeyGenStep1() (bG *EcPoint) {
	x, y := curve.ScalarBaseMult(p.b.Bytes())
	return &EcPoint{
		X: x,
		Y: y,
	}
}

func (p *Party2) KeyGenStep2(aG *EcPoint) (beta *big.Int, ek *paillier.PublicKey, err error) {
	pubKeyX, pubKeyY := curve.ScalarMult(aG.X, aG.Y, p.b.Bytes())
	xFieldVal := &secp256k1.FieldVal{}
	yFieldVal := &secp256k1.FieldVal{}
	xFieldVal.SetByteSlice(pubKeyX.Bytes())
	yFieldVal.SetByteSlice(pubKeyY.Bytes())
	p.PubKey = secp256k1.NewPublicKey(xFieldVal, yFieldVal)

	paillierPrivateKey, paillierPublicKey, err := paillier.NewKeyPair(runtime.NumCPU())
	if err != nil {
		return nil, nil, err
	}

	p.dk = paillierPrivateKey
	p.ek = paillierPublicKey

	beta, _, err = p.ek.Encrypt(p.b)
	if err != nil {
		return nil, nil, err
	}

	return beta, p.ek, nil
}

func (p *Party2) SignStep1() (k1G *EcPoint) {
	p.k2 = crypto.RandomNum(curve.N)
	x, y := curve.ScalarBaseMult(p.k2.Bytes())
	return &EcPoint{
		X: x,
		Y: y,
	}
}

// SignStep2 r = k1k2G
func (p *Party2) SignStep2(k1G *EcPoint) {
	x, y := curve.ScalarMult(k1G.X, k1G.Y, p.k2.Bytes())
	p.r = &EcPoint{
		X: x,
		Y: y,
	}
}

// SignStep3
func (p *Party2) SignStep3(c *big.Int, msg []byte) (s *big.Int, r *big.Int, err error) {
	k2Inv := new(big.Int).ModInverse(p.k2, curve.N)
	d, err := p.dk.Decrypt(c)
	if err != nil {
		return nil, nil, err
	}

	s = new(big.Int).Mul(k2Inv, d)
	s = new(big.Int).Mod(s, curve.N)

	if isValid := ecdsa.Verify(p.PubKey.ToECDSA(), msg, p.r.X, s); !isValid {
		return nil, nil, fmt.Errorf("verify fail")
	}
	return s, p.r.X, nil
}
