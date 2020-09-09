package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/miracl/core/go/core"
	"github.com/miracl/core/go/core/BN254"
)

// Function to Initialise the Random Number Generator (call only once at beginning of program!!!)
// Since the curve order defines how many unique curve points there are, to get a random point (by multiplying the generator and alpha) we need alpha to be a random number between 1 and the curve order q, as such we use q as the modulus in Randomnum()
// rng is a random number generator - here we can use the rng from Rand.go
// In order to instantiate rng, we also need a seed as source for the randomness. This seed should typically be a non-fixed seed, as we will otherwise get the same output every time. Hence we use time.Now().UnixNano() --> see https://golang.org/pkg/math/rand/ for more info -> we'll use package math/rand for this, using its generator and the non-fixed seed to create the seed for our core rng.
func initRNG() *core.RAND {
	var raw [128]byte

	seed := rand.NewSource(time.Now().UnixNano())
	r := rand.New(seed)

	rng := core.NewRAND()
	rng.Clean()

	// TODO - check if this is truly non-deterministic!
	for i := 0; i < 128; i++ {
		raw[i] = byte(r.Intn(255)) // 255 as that is the largest number that can be stored in a byte!
	}

	rng.Seed(128, raw[:])
	return rng
}

// Setup takes l -
// TODO: what about lambda? Does it make sense in this implementation via curve?
func setup(l int) (p *BN254.BIG, g1 *BN254.ECP, g2 *BN254.ECP2, helements, kelements []*BN254.ECP, omega *BN254.FP12) {
	// ----------- Setup 1
	// 1. Generate bilinear groups of order p
	// - already done once you chose the curve
	// TODO - Make setup "generic" by using different curves --> write a getParameter func for each curve
	p = BN254.NewBIGints(BN254.Modulus)
	q := BN254.NewBIGints(BN254.CURVE_Order) // TODO - maybe call this r

	// ----------- Setup 2
	// 2. Select two random elements g1 in G1 and g2 in G2
	// note, these have to be generators, to make sure that we receive valid points on the curve, if we multiply with these points
	g1 = BN254.ECP_generator()
	g2 = BN254.ECP2_generator()

	// ----------- Setup 3
	// 3. Select random exponent alpha in Zp
	// TODO - move seed stuff up to beginning of main, to make sure we only seed it once
	rng := initRNG() // Initialise Random number generator

	alpha := BN254.Randomnum(q, rng) // select random number

	// ----------- Setup 4
	// 4. Select random group elements
	// h0 , h1,0  , h1,1  , ... hl,0 , hl,1 in G1
	// all in one slice, so to get the right elements, be careful to leave out first one (h0) and do mod 2
	hrands := make([]*BN254.BIG, 2*l+1)   // slice for random numbers
	helements = make([]*BN254.ECP, 2*l+1) // Slice for resulting random group elements of G1
	for i := 0; i < 2*l+1; i++ {
		hrands[i] = BN254.Randomnum(q, rng)
		helements[i] = BN254.G1mul(g1, hrands[i])
	}

	// k0, ... kl,1 in G1
	krands := make([]*BN254.BIG, 2*l+1)   // slice for random numbers
	kelements = make([]*BN254.ECP, 2*l+1) // Slice for resulting random group elements of G1
	for i := 0; i < 2*l+1; i++ {
		krands[i] = BN254.Randomnum(q, rng)
		kelements[i] = BN254.G1mul(g1, krands[i])
	}

	// ----------- Setup 5
	// 5. Return secret master key MK = g1^alpha
	// note: In BESTIE, the groups in the pairings are written as multiplicative groups. However, g1^alpha really represents a multiplikation of g1 * alpha

	// mk := BN254.G1mul(g1, alpha)
	// TODO - work with different packages, so that mk can be called by keygen function, needs to be secret

	// ----------- Setup 6
	// 6. Return Public Key / Public Parameters
	// Note, we cannot return the bilinear group (p,G1,G2,GT,e) here, as these are merely available by using the same curve. But by using the same curve in the other algorithms, there parameters are available anyways --> are these then still secure?

	// TODO - this really only makes sense here if we work with different functions or even packages, so that decrypt cannot access any keys that are not within these PK parameters

	// compute pairing Omega = e(g1,g2)^alpha
	omega = BN254.Ate(g2, g1)
	omega = BN254.Fexp(omega)
	omega = omega.Pow(alpha)

	// Test if pairing pow works, i.e. test if e(g1,g2)^alpha is same as e(g1^alpha,g2) --> works!
	// omegatest := BN254.Ate(g2, mk)
	// omegatest = BN254.Fexp(omegatest)

	// fmt.Println("Omega: ", omega.ToString(), "")
	// fmt.Println("Omegatest: ", omegatest.ToString(), "")
	// fmt.Println(omega.Equals(omegatest))

	return p, g1, g2, helements, kelements, omega

	// ----------- Print Stuff / Test
	// fmt.Println("\n\n")
	// fmt.Println("-------  SETUP  ---------")
	// fmt.Println("The Modulus p is: (", p, ")")
	// fmt.Printf("P:\t%s\n", p.ToString())
	// fmt.Println(new(big.Int).SetString(p.ToString(), 16))
	// fmt.Println("The Curve Order q(or r) is: (", q, ")")
	// fmt.Printf("Q:\t%s\n", q.ToString())
	// fmt.Println(new(big.Int).SetString(q.ToString(), 16))
	// fmt.Println("\n\n")
	// fmt.Println("The Point G1: ", g1, "")
	// fmt.Println("The Point G2: ", g2, "")
	// fmt.Println("The random exponent alpha: ", alpha, " \n")

	// fmt.Println("Master Key (secret): ", mk, " - is this a point in G1? - ", BN254.G1member(mk), " ")

	// for i := 0; i < 2*l+1; i++ {
	// 	value2 := hrands[i].ToString()
	// 	if i == 0 {
	// 		fmt.Printf("h_%d = %s\n", i, value2)
	// 		fmt.Println(helements[i])
	// 	} else if i%2 == 0 {
	// 		fmt.Printf("h_%d,%d = %s\n", i/2, 1, value2)
	// 		fmt.Println(helements[i])
	// 	} else {
	// 		fmt.Printf("h_%d,%d = %s\n", (i+1)/2, 0, value2)
	// 		fmt.Println(helements[i])
	// 	}
	// 	val := BN254.G1member(helements[1])
	// 	fmt.Println("Is Point member of G1? ", val, " ")
	// }

	// for i := 0; i < 2*l+1; i++ {
	// 	value2 := krands[i].ToString()
	// 	if i == 0 {
	// 		fmt.Printf("k_%d = %s\n", i, value2)
	// 		fmt.Println(kelements[i])
	// 	} else if i%2 == 0 {
	// 		fmt.Printf("k_%d,%d = %s\n", i/2, 1, value2)
	// 		fmt.Println(kelements[i])
	// 	} else {
	// 		fmt.Printf("k_%d,%d = %s\n", (i+1)/2, 0, value2)
	// 		fmt.Println(kelements[i])
	// 	}
	// 	val := BN254.G1member(kelements[1])
	// 	fmt.Println("Is Point member of G1? ", val, " ")
	// }
}

func keyGen() {

}

func main() {

	// ----------- (Global) Parameters
	l := 4 // ID bit Length

	// Call Setup to get public parameters
	p, g1, g2, helements, kelements, omega := setup(l)

	// Call KeyGen to generate private key
	// TODO - try this for several users later
	keyGen()

	fmt.Println("p: ", p, "")
	fmt.Println("g1: ", g1, "")
	fmt.Println("g2: ", g2, "")
	fmt.Println("helements: ", helements, "")
	fmt.Println("kelements: ", kelements, "")
	fmt.Println("omega: ", omega, "")

}
