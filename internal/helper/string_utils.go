package helper

import (
	"unicode"
)

func IsAllDigits(s string) bool {
	if s == "" {
		return false
	} // end if
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		} // end if
	} // end for
	return true
} // end IsAllDigits()
