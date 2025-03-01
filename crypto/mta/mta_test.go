package mta

import (
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestMtA(t *testing.T) {
	bitNum, _ := big.NewInt(0).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)

	testCases := []struct {
		a, b string // 문자열로 정의 후 big.Int로 변환
	}{
		{"2", "3"},
		{"5", "7"},
		{"10", "20"},
		{"1", "123456789"},
		{"123456789", "1"},
		{"123456789", "987654321"},
		{"987654321", "123456789"},
		{"10000000000", "1000000000000000"},
		{"123456789123456789123456789123456789123456789", "987654321987654321987654321987654321987654321"},
		{"987654321987654321987654321987654321987654321", "123456789123456789123456789123456789123456789"},
		{"123456789123456789123456789123456789123456789123456789", "987654321987654321987654321987654321987654321987654321"},
		{"987654321987654321987654321987654321987654321987654321", "123456789123456789123456789123456789123456789123456789"},
		{"123456789123456789123456789123456789123456789123456789123456789", "987654321987654321987654321987654321987654321987654321987654321"},
		{"987654321987654321987654321987654321987654321987654321987654321", "123456789123456789123456789123456789123456789123456789123456789"},
		{bitNum.String(), bitNum.String()},
	}

	for _, tc := range testCases {
		t.Run("MtA "+tc.a+"*"+tc.b, func(t *testing.T) {
			a, _ := big.NewInt(0).SetString(tc.a, 10)
			b, _ := big.NewInt(0).SetString(tc.b, 10)
			g := big.NewInt(3)
			rho := 256

			p, _ := big.NewInt(0).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
			alice := NewAlice(a, p, g, p, rho)
			// Bob 생성
			bob := NewBob(b, p, g, p, rho)

			otAList := bob.Step1()
			otBList := alice.Step1(otAList)

			// Step1: Bob이 Alice의 공개 키를 이용해 암호화
			c0List, c1List, nonceK0List, nonceK1List, y, err := bob.Step2(otBList)
			assert.NoError(t, err)

			// Step2: Alice가 Bob의 암호문을 복호화하여 x 계산
			x, err := alice.Step2(c0List, c1List, nonceK0List, nonceK1List)
			assert.NoError(t, err)

			// 결과 검증: x + y == a * b mod modulus
			ab := new(big.Int).Mul(a, b)
			ab.Mod(ab, p)
			sum := new(big.Int).Add(x, y)
			sum.Mod(sum, p)

			assert.Equal(t, ab, sum, "MtA 프로토콜 실패")
		})
	}
}
