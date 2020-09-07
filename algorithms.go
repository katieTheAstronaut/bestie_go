package main

import (
	"fmt"
	"math/rand"
	"time"

	// "math/rand"
	// "os"
	// "time"

	// "github.com/miracl/core/go/core"
	"github.com/miracl/core/go/core"
	"github.com/miracl/core/go/core/BN254"
)

func main() {

	// ----------- Setup 1
	// 1. Generate bilinear groups of order p
	// - already done once you chose the curve
	// TODO - Make setup "generic" by using different curves --> write a getParameter func for each curve
	p := BN254.NewBIGints(BN254.Modulus)
	q := BN254.NewBIGints(BN254.CURVE_Order) // TODO - maybe call this r

	// ----------- Setup 2
	// 2. Select two random elements g1 in G1 and g2 in G2
	// note, these have to be generators, to make sure that we receive valid points on the curve, if we multiply with these points
	g1 := BN254.ECP_generator()
	g2 := BN254.ECP2_generator()

	// ----------- Setup 3
	// 3. Select random exponent alpha in Zp
	// Since the curve order defines how many unique curve points there are, to get a random point (by multiplying the generator and alpha) we need alpha to be a random number between 1 and the curve order q, as such we use q as the modulus in Randomnum()

	// rng is a random number generator - here we can use the rng from Rand.go
	// In order to instantiate rng, we also need a seed as source for the randomness. This seed should typically be a non-fixed seed, as we will otherwise get the same output every time. Hence we use time.Now().UnixNano() --> see https://golang.org/pkg/math/rand/ for more info -> we'll use package math/rand for this
	// TODO - move seed stuff up to beginning of main, to make sure we only seed it once
	seed := rand.NewSource(time.Now().UnixNano())
	rng := core.NewRAND()

	alpha := BN254.Randomnum(q, rng)

	// ----------- MAIN

	fmt.Println(g1)
	fmt.Println(g2)

}
