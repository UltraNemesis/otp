# otp
Go package for HOTP (RFC4226) and TOTP (RFC6238)

[![GoDoc](https://godoc.org/github.com/UltraNemesis/otp?status.svg)](https://godoc.org/github.com/UltraNemesis/otp)

### Usage

##### Generate secret of default size (20 bytes)

    secret, _ := otp.NewSecret()

##### Generate secret of specified size (bytes)

    secret, _ := otp.NewSecretWithSize(otp.SECERT_SIZE_32)

##### Generate URI for HTOP (Counter value must be non-zero)

    hotpURI := otp.URI(secret, &otp.Options{
    	User:    "testuser",
    	Issuer:  "testissuer",
    	Counter: 1,
    })

##### Generate URI for HTOP (Counter value is always zero for TOTP)

    totpURI := otp.URI(secret, &otp.Options{
    	User:   "testuser",
    	Issuer: "testissuer",
    })

##### Generate QR code for HOTP/TOTP

	qr, uri, qrErr := otp.QR(secret, &otp.Options{
		User:   "testuser",
		Issuer: "testissuer",
	})

##### Generate HOTP of length 4 and next counter value of 20

	hotp := otp.HOTP(sha1.New, secret, 20, otp.DIGITS_4)

##### Generate TOTP with recycle rate of 45 sec and length 8

	totp := otp.TOTP(sha1.New, secret, time.Now(), otp.PERIOD_45, otp.DIGITS_8)

##### Generate Google Authenticator compatible HOTP
	ghotp := otp.GOOGLE_HOTP(secret, 1)

##### Generate Google Authenticator compatible TOTP
	gtotp := otp.GOOGLE_TOTP(secret)

