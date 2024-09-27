package jwt

import "time"

var (
	defaultExpire = 10 * time.Minute
	encryptionKey = "sign key"
)
