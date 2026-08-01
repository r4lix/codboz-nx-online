package bitdemon

import (
	"encoding/hex"
	"testing"
)

func TestTiger192PublishedVectors(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		digest  string
	}{
		{name: "empty", payload: "", digest: "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3"},
		{name: "a", payload: "a", digest: "77befbef2e7ef8ab2ec8f93bf587a7fc613e247f5f247809"},
		{name: "abc", payload: "abc", digest: "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93"},
		{name: "Tiger", payload: "Tiger", digest: "dd00230799f5009fec6debc838bb6a27df2b9d6f110c7937"},
		{
			name:    "multiple blocks",
			payload: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
			digest:  "f71c8583902afb879edfe610f82c0d4786a3a534504486b5",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Tiger192([]byte(test.payload))
			if hex.EncodeToString(got[:]) != test.digest {
				t.Fatalf("Tiger192(%q) = %x, want %s", test.payload, got, test.digest)
			}
		})
	}
}
