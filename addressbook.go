package main

import (
)

type AddressBookEntry struct {
	Value string
	Type string
}

type Person []AddressBookEntry
type AddressBook map[string]Person

func LookUpAddressBookByEntryValue(abook *AddressBook, v string) (name string) {
	for name, person := range *abook {
		for _, entry := range person {
			if entry.Value == v {
				return name
			}
		}
	}
	return name
}

func LookUpAddressBookByEntryType(abook *AddressBook, t string) (name string) {
	for name, person := range *abook {
		for _, entry := range person {
			if entry.Type == t {
				return name
			}
		}
	}
	return name
}


