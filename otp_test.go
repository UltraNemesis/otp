// otp_test.go
package otp

import (
	"testing"
)

func BenchmarkNewSecret(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {

		for pb.Next() {
			NewSecret()
		}
	})
}

func BenchmarkRegistration(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {

		for pb.Next() {
			secret, _ := NewSecret()
			QR(secret, &Options{
				User:   "testuser",
				Issuer: "testissuer",
			})
		}
	})
}

func BenchmarkGoogleTOTP(b *testing.B) {
	secret, _ := NewSecret()

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			GOOGLE_TOTP(secret)
		}
	})
}
