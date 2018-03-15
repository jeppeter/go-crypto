// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

// from PKCS#7:
type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

var (
	oidSHA1   = asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26})
	oidSHA256 = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1})
)

func formatByte(data []byte) string {
	var s string = ""
	var i int
	var b byte

	s += "["
	for i, b = range data {
		if i > 0 {
			s += ","
		}
		s += fmt.Sprintf("0x%02x", b)
	}
	s += "]"
	s += fmt.Sprintf("[%d]", len(data))
	return s
}

func verifyMac(macData *macData, message, password []byte) error {
	var expectedMAC []byte
	if !macData.Mac.Algorithm.Algorithm.Equal(oidSHA1) &&
		!macData.Mac.Algorithm.Algorithm.Equal(oidSHA256) {
		return NotImplementedError("unknown digest algorithm: " + macData.Mac.Algorithm.Algorithm.String())
	}

	if macData.Mac.Algorithm.Algorithm.Equal(oidSHA1) {
		key := pbkdf(sha1Sum, 20, 64, macData.MacSalt, password, macData.Iterations, 3, 20)
		mac := hmac.New(sha1.New, key)
		mac.Write(message)
		expectedMAC = mac.Sum(nil)
	} else if macData.Mac.Algorithm.Algorithm.Equal(oidSHA256) {
		key := pbkdf(sha256Sum, 32, 64, macData.MacSalt, password, macData.Iterations, 3, 20)
		mac := hmac.New(sha256.New, key)
		mac.Write(message)
		expectedMAC = mac.Sum(nil)
	}

	fmt.Printf("iterations %d\ndigest\n%v\nexpectMAC\n%v\n", macData.Iterations, formatByte(macData.Mac.Digest), formatByte(expectedMAC))
	if !hmac.Equal(macData.Mac.Digest, expectedMAC) {
		return ErrIncorrectPassword
	}
	return nil
}
