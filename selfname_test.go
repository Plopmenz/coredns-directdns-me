package directdns_me

import (
	"net"
	"testing"
)

func TestIsSelfLabel(t *testing.T) {
	self := net.ParseIP("200:76d6:609:481c:8c26:17cf:cd46:8033")
	cases := map[string]bool{
		"200-76d6-609-481c-8c26-17cf-cd46-8033":   true,  // as yggdrasilctl prints it
		"200-76d6-0609-481c-8c26-17cf-cd46-8033":  true,  // one group zero-padded
		"0200-76d6-0609-481c-8c26-17cf-cd46-8033": true,  // fully expanded
		"200-76d6-609-481c-8c26-17cf-cd46-8034":   false, // another node
		"public":                                  false,
		"":                                        false,
	}
	for label, want := range cases {
		if got := isSelfLabel(label, self); got != want {
			t.Errorf("isSelfLabel(%q) = %v, want %v", label, got, want)
		}
	}
}
