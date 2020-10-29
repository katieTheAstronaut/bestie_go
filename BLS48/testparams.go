package main

import (
	"fmt"
	"time"

	"github.com/miracl/core/go/core/BLS48581"
)

func main() {

	// measure time of algorithms
	init := time.Now()

	// Initialise Random number generator
	initRNG()

	// Call KeyGen to generate private key
	// TODO - try this for several users later
	id := "0110" // User's ID
	cl := "***0" // CL - covered list of IDs
	rl := "*100" // RL - revoked list of ids

	l := len(id) // ID bit length
	// TODO - if id is not part of cl or part of rl, the program throws runtime error nil pointer exception -> make sure program simply stops with error message and does not go on!

	// Call Setup to get public parameters
	pubKey, mk, alpha := setup(l) // TODO - only pubkey should be returned here?

	// Call KeyGen to get private key SK (parameters)
	// TODO - get mk and alpha from setup (through other func/package?)
	secKey, r, g1AlphaMinOmega, g1AlphaOmega := keyGen(id, mk, pubKey, alpha)

	// Create message M in GT
	q := BLS48581.NewBIGints(BLS48581.CURVE_Order)
	// TODO - remove q, as it needs to stay secret?
	// TODO - this is wrong!!!, but for now we will use a random GT element as message
	rand1 := BLS48581.Randomnum(q, rng)
	m1 := BLS48581.G1mul(pubKey.g1, rand1)
	rand2 := BLS48581.Randomnum(q, rng)
	m2 := BLS48581.G2mul(pubKey.g2, rand2)
	message := BLS48581.Ate(m2, m1)
	message = BLS48581.Fexp(message)
	val := BLS48581.GTmember(message)
	fmt.Println("message is GT member: ", val)
	fmt.Println("original message: ", message.ToString())

	// Call Encrypt
	cipher, krl := encrypt(cl, rl, pubKey, message, r, g1AlphaMinOmega)

	mes := decrypt(cl, rl, id, secKey, cipher, krl, r, g1AlphaOmega)

	functional := message.Equals(mes) // test if encrypted message is same as decrypted message
	fmt.Println("\n")
	fmt.Println("Message is same: ", functional)

	// fmt.Println(x0, y0, xelements, yEven, yOdd, z, c0, c1, c2, c3)

	// end of stopwatch
	fmt.Println("\n")
	elapsed := time.Since(init)
	fmt.Printf("Binomial took %s", elapsed)

}
