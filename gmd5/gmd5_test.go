package gmd5

import "testing"

func TestSum(t *testing.T) {
	if Sum([]byte("this is content")) != "b7fcef7fe745f2a95560ff5f550e3b8f" {
		t.Errorf("gmd5 is error")
	}
}

func BenchmarkSum(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if Sum([]byte("this is content")) != "b7fcef7fe745f2a95560ff5f550e3b8f" {
			b.Errorf("gmd5 is error")
			return
		}
	}
}
