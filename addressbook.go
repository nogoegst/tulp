package main

import (
	"bytes"
)

type Person struct {
	OTRFingerprints [][]byte
	OnionAddresses  []string
}

type AddressBook map[string]Person

func LookUpAddressBookByFingerprint(abook *AddressBook, FP []byte) (name string) {
	for name, person := range *abook {
		for _, fp := range person.OTRFingerprints {
			if bytes.Equal(fp, FP) {
				return name
			}
		}
	}
	return name
}


