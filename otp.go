// otp.go
package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"net/url"
	"strconv"
	"time"

	"rsc.io/qr"
)

type SecretSize uint8

// Standard Secret sizes
const (
	SECRET_SIZE_16      SecretSize = 16
	SECRET_SIZE_20      SecretSize = 20
	SECERT_SIZE_32      SecretSize = 32
	SECRET_SIZE_64      SecretSize = 64
	SECRET_SIZE_MIN     SecretSize = SECRET_SIZE_16
	SECRET_SIZE_DEFAULT SecretSize = SECRET_SIZE_20
)

type Digit uint8

// Standard OTP Lengths
const (
	DIGITS_4   Digit = 4
	DIGITS_6   Digit = 6
	DIGITS_8   Digit = 8
	DIGITS_MIN Digit = DIGITS_4
	DIGITS_MAX Digit = 9
)

type Period uint8

// Standard TOTP Periods
const (
	PERIOD_30 Period = 30
	PERIOD_45 Period = 45
	PERIOD_60 Period = 60
)

type Algorithm string

// Standard Hashing Algorithms
const (
	SHA1   Algorithm = "sha1"
	SHA256 Algorithm = "sha256"
	SHA512 Algorithm = "sha512"
)

var padding = []string{
	0: "",
	1: "0",
	2: "00",
	3: "000",
	4: "0000",
	5: "00000",
	6: "000000",
	7: "0000000",
	8: "00000000",
	9: "000000000",
}

var digits = []uint32{
	1: 10,
	2: 100,
	3: 1000,
	4: 10000,
	5: 100000,
	6: 1000000,
	7: 10000000,
	8: 100000000,
	9: 1000000000,
}

type Options struct {
	User      string
	Issuer    string
	Counter   uint64
	Period    Period
	Digits    Digit
	Algorithm Algorithm
}

// Generate a new secret of default size (20 bytes)
func NewSecret() (secret string, err error) {
	secret, err = NewSecretWithSize(SECRET_SIZE_DEFAULT)

	return
}

// Generate a new secret of specified size. Mininum size is 16 bytes
func NewSecretWithSize(size SecretSize) (secret string, err error) {
	if size < SECRET_SIZE_MIN {
		err = errors.New("Secret is too small")
	} else {
		key := make([]byte, size)

		if _, randErr := io.ReadFull(rand.Reader, key); randErr != nil {
			err = randErr
		}

		secret = base32.StdEncoding.EncodeToString(key)
	}

	return
}

// Generate a Time based OTP that is compatible with Google Authenticator
func GOOGLE_TOTP(secret string) (otp string) {
	otp = TOTP_SHA1(secret, time.Now(), PERIOD_30, DIGITS_6)

	return
}

// Generate a Hmac based OTP that is compatible with Google Authenticator
func GOOGLE_HOTP(secret string, counter uint64) (otp string) {
	otp = HOTP_SHA1(secret, counter, DIGITS_6)

	return
}

// Generate a Time based OTP using Sha1 as the Hashing Algorithm for HMac
func TOTP_SHA1(secret string, timeStamp time.Time, period Period, length Digit) (otp string) {
	otp = TOTP(sha1.New, secret, timeStamp, period, length)

	return
}

// Generate a Hmac based OTP using Sha1 as the Hashing Algorithm for HMac
func HOTP_SHA1(secret string, counter uint64, length Digit) (otp string) {
	otp = HOTP(sha1.New, secret, counter, length)

	return
}

// Generate a Time based OTP
func TOTP(hasher func() hash.Hash, secret string, timeStamp time.Time, period Period, length Digit) (otp string) {
	otp = HOTP(hasher, secret, uint64(timeStamp.Unix()/int64(period)), length)

	return
}

// Generate a Hmac based OTP
func HOTP(hasher func() hash.Hash, secret string, counter uint64, length Digit) (otp string) {
	if length >= DIGITS_MIN && length <= DIGITS_MAX {
		otp = compute(hasher, secret, counter, uint8(length))
	}

	return
}

// Generate OATH URI compatible with Authenticator Apps. The format is documented
// at https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func URI(secret string, options *Options) string {
	values := url.Values{}
	uri := url.URL{
		Scheme: "otpauth",
	}

	if options.Counter > 0 {
		uri.Host = "hotp"
		values.Add("counter", strconv.FormatUint(options.Counter, 10))
	} else {
		uri.Host = "totp"

		if options.Period > 0 {
			values.Add("period", strconv.FormatUint(uint64(options.Period), 10))
		}
	}

	if len(options.Issuer) > 0 {
		uri.Path = options.Issuer + ":" + options.User
		values.Add("issuer", options.Issuer)
	} else {
		uri.Path = options.User
	}

	values.Add("secret", secret)

	if len(options.Algorithm) > 0 {
		values.Add("algorithm", string(options.Algorithm))
	}

	if options.Digits == DIGITS_6 || options.Digits == DIGITS_8 {
		values.Add("digits", strconv.FormatUint(uint64(options.Digits), 10))
	}

	uri.RawQuery = values.Encode()

	return uri.String()
}

// Generate OATH URI and QR code compatible with Authenticator Apps.
func QR(secret string, options *Options) (qrCode string, uri string, err error) {
	uri = URI(secret, options)

	code, qrErr := qr.Encode(uri, qr.Q)

	if qrErr != nil {
		err = qrErr
	} else {
		qrCode = `data:image/png;base64,` + base64.StdEncoding.EncodeToString(code.PNG())
	}

	return
}

// Compute Hmac based OTP
func compute(hasher func() hash.Hash, secret string, counter uint64, length uint8) (otp string) {
	var code uint64 = 0

	key, keyErr := base32.StdEncoding.DecodeString(secret)

	if keyErr == nil {
		var bytes [8]byte

		binary.BigEndian.PutUint64(bytes[:], counter)

		hash := hmac.New(hasher, key)

		_, hashErr := hash.Write(bytes[:])

		if hashErr == nil {
			sum := hash.Sum(nil)

			offset := sum[len(sum)-1] & 0x0F

			truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7FFFFFFF
			code = uint64(truncated % digits[length])
		}
	}

	otp = otpformat(code, length)

	return
}

// Format the numeric OTP code into string with necessary 0 padding
func otpformat(code uint64, length uint8) string {
	codeStr := strconv.FormatUint(code, 10)

	return padding[length-uint8(len(codeStr))] + codeStr
}
