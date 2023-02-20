package gsha256

import "testing"

func TestSum(t *testing.T) {
	if Sum([]byte("this is content")) != "630a118958070c95a69efbcfb8a212a84167173a3bf6e8a334b0d45504b00bf5" {
		t.Errorf("gsha256 is error")
	}
}

func BenchmarkSum(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if Sum([]byte("this is content")) != "630a118958070c95a69efbcfb8a212a84167173a3bf6e8a334b0d45504b00bf5" {
			b.Errorf("gsha256 is error")
			return
		}
	}
}
