package main

import (
	"fmt"
	"time"

	"github.com/miracl/core/go/core/BN462"
)

func main() {

	initRNG()

	// 128
	// id := "00000110000001100000011000000110000001100000011000000110000001100000011000000110000001100000011000000110000001100000011000000110" // User's ID
	// cl := "******************************************************************************************************************************10" // CL - covered list of IDs
	// rl := "******************************************************************************************************************************00" // RL - revoked list of ids

	// // 64
	// id := "0000011000000110000001100000011000000110000001100000011000000110" // User's ID
	// cl := "**************************************************************10" // CL - covered list of IDs
	// rl := "**************************************************************00" // RL - revoked list of ids

	// // 32
	// id := "00000110000001100000011000000110"
	// cl := "******************************10"
	// rl := "******************************00"

	// 16
	// id := "0000011000000110"
	// cl := "**************10"
	// rl := "**************00"

	// // 8
	id := "00000110"
	cl := "******10"
	rl := "******00"

	l := len(id)

	pubKey, mk, alpha := setup(l)
	secKey, r, g1AlphaMinOmega, g1AlphaOmega := keyGen(id, mk, pubKey, alpha)

	// Create message M in GT
	q := BN462.NewBIGints(BN462.CURVE_Order)
	rand1 := BN462.Randomnum(q, rng)
	m1 := BN462.G1mul(pubKey.g1, rand1)
	rand2 := BN462.Randomnum(q, rng)
	m2 := BN462.G2mul(pubKey.g2, rand2)
	message := BN462.Ate(m2, m1)
	message = BN462.Fexp(message)

	// Call Encrypt
	cipher, krl := encrypt(cl, rl, pubKey, message, r, g1AlphaMinOmega)

	init := time.Now()
	mes := decrypt(cl, rl, id, secKey, cipher, krl, r, g1AlphaOmega)
	// end of stopwatch
	elapsed := time.Since(init)
	fmt.Println("Dec for ", l, " took %s", elapsed)

	functional := message.Equals(mes)
	fmt.Println("Message is same: ", functional)

}
