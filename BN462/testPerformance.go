package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/miracl/core/go/core/BN462"
)

type skJSON struct {
	X0        string
	Xelements []string
	Y0        string
	YEven     []string
	YOdd      []string
	Z         string
}

// func main() {

// 	initRNG()

// 	l := 128

// 	// get test ID, CL and RL
// 	id, s := getID(l)

// 	fmt.Println("\n")
// 	fmt.Println("-------  Performance Test  ---------")
// 	fmt.Println("Curve: BN462")

// 	// Run Setup and KeyGen
// 	pubKey, mk := setup(l)
// 	secKey := keyGen(id, mk, pubKey)

// 	// Test Encryption Performance
// 	message := createRandomM(pubKey)
// 	cipher := testEncryption(message, s, pubKey, l)

// 	// Test Decryption Performance
// 	mes := testDecryption(s, id, secKey, cipher, l)

// 	// Test if message input equals message output
// 	checkMessage(message, mes)

// 	// Write SK to file
// 	skToFile(secKey)
// }

// function to test Encryption performance
func testEncryption(message *BN462.FP12, s *subset, pubKey *pk, l int) (cipher *hdr) {

	init := time.Now()

	cipher = encrypt(s, pubKey, message)

	elapsed := time.Since(init)

	fmt.Println("Encryption for l = ", l, " took", elapsed)

	return cipher
}

// function to test Decryption performance
func testDecryption(s *subset, id string, secKey *sk, cipher *hdr, l int) (mes *BN462.FP12) {
	init := time.Now()

	mes, _ = decrypt(s, id, secKey, cipher)

	elapsed := time.Since(init)

	fmt.Println("Decryption for l = ", l, " took", elapsed)

	return mes
}

// function to test message validity
func checkMessage(inputMes, outputMes *BN462.FP12) {
	equality := inputMes.Equals(outputMes)
	fmt.Println("Input Message is same as Output Message: ", equality)
}

// function to write SK to file
func skToFile(secKey *sk) {
	skJ := &skJSON{
		X0:        secKey.x0.ToString(),
		Xelements: toStrArr(secKey.xelements),
		Y0:        secKey.y0.ToString(),
		YEven:     toStrArr(secKey.yEven),
		YOdd:      toStrArr(secKey.yOdd),
		Z:         secKey.z.ToString(),
	}

	file, _ := json.Marshal(skJ)
	_ = ioutil.WriteFile("sk.json", file, 0777)
}

// function to turn ECP slice to String slice
// helper function for skToFile()
func toStrArr(a []*BN462.ECP) []string {
	result := make([]string, len(a))

	for i := 0; i < len(a); i++ {
		result[i] = a[i].ToString()
	}
	return result
}

// Function to create random message
func createRandomM(pubKey *pk) *BN462.FP12 {
	// Create message M in GT
	q := BN462.NewBIGints(BN462.CURVE_Order)
	rand1 := BN462.Randomnum(q, rng)
	m1 := BN462.G1mul(pubKey.g1, rand1)
	rand2 := BN462.Randomnum(q, rng)
	m2 := BN462.G2mul(pubKey.g2, rand2)
	message := BN462.Ate(m2, m1)
	message = BN462.Fexp(message)

	return message
}

// function to generate test ID, CL and RL for specific length
func getID(l int) (id string, s *subset) {

	var cl, rl string

	switch l {
	case 128:
		id = "00000110000001100000011000000110000001100000011000000110000001100000011000000110000001100000011000000110000001100000011000000110"
		cl = "******************************************************************************************************************************1*"
		rl = "******************************************************************************************************************************11"
	case 64:
		id = "0000011000000110000001100000011000000110000001100000011000000110"
		cl = "**************************************************************10"
		rl = "**************************************************************00"
	case 32:
		id = "00000110000001100000011000000110"
		cl = "******************************10"
		rl = "******************************00"
	case 16:
		id = "0000011000000110"
		cl = "**************10"
		rl = "**************00"
	case 8:
		id = "00000110"
		cl = "******10"
		rl = "******00"
	}

	s = &subset{cl, rl}

	return id, s
}
