package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/miracl/core/go/core/BN254"
)

type skJSON struct {
	X0        string
	Xelements []string
	Y0        string
	YEven     []string
	YOdd      []string
	Z         string
}

func main() {

	initRNG()

	l := 128

	// get test ID, CL and RL
	id, cl, rl := getID(l)

	// Run Setup and KeyGen
	pubKey, mk, alpha := setup(l)
	secKey, r, g1AlphaMinOmega, g1AlphaOmega := keyGen(id, mk, pubKey, alpha)

	// Test Encryption Performance
	message := createRandomM(pubKey)
	cipher, krl := testEncryption(message, cl, rl, pubKey, r, g1AlphaMinOmega, l)

	// Test Decryption Performance
	mes := testDecryption(cl, rl, id, secKey, cipher, krl, r, g1AlphaOmega, l)

	// Test if message input equals message output
	checkMessage(message, mes)

	// Write SK to file
	skToFile(secKey)
}

// function to test Encryption performance
func testEncryption(message *BN254.FP12, cl, rl string, pubKey *pk, r *BN254.BIG, g1AlphaMinOmega *BN254.ECP, l int) (cipher *hdr, krl *BN254.ECP) {

	init := time.Now()

	cipher, krl = encrypt(cl, rl, pubKey, message, r, g1AlphaMinOmega)

	elapsed := time.Since(init)

	fmt.Println("Encryption for l = ", l, " took %s", elapsed)

	return cipher, krl
}

// function to test Decryption performance
func testDecryption(cl, rl, id string, secKey *sk, cipher *hdr, krl *BN254.ECP, r *BN254.BIG, g1AlphaOmega *BN254.ECP, l int) (mes *BN254.FP12) {
	init := time.Now()

	mes = decrypt(cl, rl, id, secKey, cipher, krl, r, g1AlphaOmega)

	elapsed := time.Since(init)

	fmt.Println("Decryption for l = ", l, " took %s", elapsed)

	return mes
}

// function to test message validity
func checkMessage(inputMes, outputMes *BN254.FP12) {
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
func toStrArr(a []*BN254.ECP) []string {
	result := make([]string, len(a))

	for i := 0; i < len(a); i++ {
		result[i] = a[i].ToString()
	}
	return result
}

// Function to create random message
func createRandomM(pubKey *pk) *BN254.FP12 {
	// Create message M in GT
	q := BN254.NewBIGints(BN254.CURVE_Order)
	rand1 := BN254.Randomnum(q, rng)
	m1 := BN254.G1mul(pubKey.g1, rand1)
	rand2 := BN254.Randomnum(q, rng)
	m2 := BN254.G2mul(pubKey.g2, rand2)
	message := BN254.Ate(m2, m1)
	message = BN254.Fexp(message)

	return message
}

// function to generate test ID, CL and RL for specific length
func getID(l int) (id, cl, rl string) {

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

	return id, cl, rl
}
