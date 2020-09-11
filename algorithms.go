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

// ----------- (Global) Parameters
// TODO - do we want global parameters?
var l = 3 // ID bit Length

// Setup takes l -
// TODO: what about lambda? Does it make sense in this implementation via curve?
func setup(l int, rng *core.RAND) (p *BN254.BIG, g1 *BN254.ECP, g2 *BN254.ECP2, helements, kelements []*BN254.ECP, omega *BN254.FP12, mk *BN254.ECP, alpha *BN254.BIG) {
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
	// 3. Select random exponent alpha in Zp --> q needs to be modulus though!
	alpha = BN254.Randomnum(q, rng)

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

	mk = BN254.G1mul(g1, alpha)
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

	for i := 0; i < 2*l+1; i++ {
		value2 := hrands[i].ToString()
		if i == 0 {
			fmt.Printf("h_%d = %s\n", i, value2)
			fmt.Println(helements[i])
		} else if i%2 == 0 {
			fmt.Printf("h_%d,%d = %s\n", i/2, 1, value2)
			fmt.Println(helements[i])
		} else {
			fmt.Printf("h_%d,%d = %s\n", (i+1)/2, 0, value2)
			fmt.Println(helements[i])
		}
		// val := BN254.G1member(helements[1])
		// fmt.Println("Is Point member of G1? ", val, " ")
	}

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
	return p, g1, g2, helements, kelements, omega, mk, alpha
}

// KeyGen takes user's ID, master key, and public parameters
func keyGen(id string, mk *BN254.ECP, p *BN254.BIG, g1 *BN254.ECP, g2 *BN254.ECP2, helements, kelements []*BN254.ECP, omega *BN254.FP12, rng *core.RAND, alpha *BN254.BIG) {
	q := BN254.NewBIGints(BN254.CURVE_Order) // TODO - do not repeat yourself, consider putting this in main? but it needs to be secret

	// ----------- KeyGen 1
	// 1. Select two random exponents alpha_omega and r in Zp
	alphaOmega := BN254.Randomnum(q, rng)
	r := BN254.Randomnum(q, rng)

	// ----------- KeyGen 2
	// Create private key SK_ID

	// ---x0
	exp := alpha.Minus(alphaOmega)
	hID := BN254.NewECP()

	// while BESTIE construction theoretically notes to multiply points, in EC this means we need to add all the points of h (point addition)
	// TODO - this is ridiculously ugly, rewrite this code!
	for i := 1; i < l+1; i++ {
		if string(id[i-1]) == "0" { // TODO - perhaps make this more elegant and turn ID into slice instead of string? Then we wouldnt have to convert from string byte (string behaves like slice here) to string to compare both
			hID.Add(helements[i*2-1])
			fmt.Println(" ID ", i, " : ", helements[i*2-1], " ")
		} else if string(id[i-1]) == "1" {
			hID.Add(helements[i*2])
			fmt.Println(" ID ", i, " : ", helements[i*2], " ")
		} else {
			fmt.Println("ID could not be read")
		}

	}
	hID.Add(helements[0])
	hExp := BN254.G1mul(hID, r)
	g1AlphaOmega := BN254.G1mul(g1, exp)
	hExp.Add(g1AlphaOmega)

	x0 := hExp
	fmt.Println("x0 is the point: ", x0.ToString(), "")
	fmt.Println(id)

	// Test if adding the points for ID 010 will give the same resulting point --> it will
	// x0Test := helements[1]
	// x0Test.Add(helements[4])
	// x0Test.Add(helements[5])
	// x0Test.Add(helements[0])
	// hExpTest := BN254.G1mul(x0Test, r)
	// hExpTest.Add(g1AlphaOmega)

	// fmt.Println("x0Test is the point: ", hExpTest.ToString(), "")

	// ---x1 - xl

	xelements := make([]*BN254.ECP, l) // make a slice for x1 to xl

	for i := 1; i < l+1; i++ {
		if string(id[i-1]) == "0" { // TODO - perhaps make this more elegant and turn ID into slice instead of string? Then we wouldnt have to convert from string byte (string behaves like slice here) to string to compare both
			xelements[i-1] = BN254.G1mul(helements[i*2], r)
			fmt.Println(" x ", i, " : ", xelements[i-1].ToString(), " ")
		} else if string(id[i-1]) == "1" {
			xelements[i-1] = BN254.G1mul(helements[i*2-1], r)
			fmt.Println(" x ", i, " : ", xelements[i-1].ToString(), " ")
		} else {
			fmt.Println("ID could not be read")
		}
	}

	// -- y0

	y0 := BN254.G1mul(kelements[0], r)
	fmt.Println(y0)

	// -- y1...y2l

}

func main() {

	// Initialise Random number generator
	rng := initRNG()

	// Call Setup to get public parameters
	// pass rng as parameter, so we only need to initialise it once in main
	p, g1, g2, helements, kelements, omega, mk, alpha := setup(l, rng)

	// Call KeyGen to generate private key
	// TODO - try this for several users later
	// TODO - link id to l
	id := "010" // User's ID

	// TODO - get mk and alpha from setup (through other func/package?)
	keyGen(id, mk, p, g1, g2, helements, kelements, omega, rng, alpha)

	// fmt.Println("p: ", p, "")
	// fmt.Println("g1: ", g1, "")
	// fmt.Println("g2: ", g2, "")
	// fmt.Println("helements: ", helements, "")
	// fmt.Println("kelements: ", kelements, "")
	// fmt.Println("omega: ", omega, "")

}
