// Package util provides shared helper functions used across DVGA.
package util

import "fmt"

func IsAdminRole(value string) (bool, error) {
	switch value {
	case "admin":
		return true, nil
	case "user", "support", "helpdesk":
		return false, nil
	default:
		return false, fmt.Errorf("unknown role value %q", value)
	}
}
