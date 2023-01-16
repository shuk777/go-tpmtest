package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	gutils "github.com/Laisky/go-utils/v3"
	"github.com/google/go-attestation/attest"
)

func main() {
	nonce := make([]byte, 16)
	hash := sha256.New()
	hash.Write(nonce)
	nonceHash := hash.Sum(nil)[0:16]
	config := &attest.OpenConfig{}
	device, err := attest.OpenTPM(config)
	if err != nil {
		fmt.Println(err)
	}
	defer gutils.SilentClose(device)

	// mfrCA, _ := base64.StdEncoding.DecodeString(MFR_CA)

	akConfig := &attest.AKConfig{}
	ak, err := device.NewAK(akConfig)
	if err != nil {
		fmt.Println(err)
	}
	att, err := device.AttestPlatform(ak, nonceHash, &attest.PlatformAttestConfig{EventLog: []byte{0}})
	if err != nil {
		fmt.Println(err)
	}
	receivedPcrDigest := make([]byte, 0)
	for _, pcr := range att.PCRs {
		receivedPcrDigest = append(receivedPcrDigest, pcr.Digest...)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(receivedPcrDigest))
}
