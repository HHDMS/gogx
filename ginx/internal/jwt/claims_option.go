package jwt

import (
	"time"

	"github.com/ecodeclub/ekit/bean/option"
	"github.com/golang-jwt/jwt/v5"
)

type Options struct {
	Expire        time.Duration     // 有效期
	EncryptionKey string            // 加密密匙
	DecryptKey    string            // 解密密匙
	Method        jwt.SigningMethod // 签名方式
	Issuer        string            // 签发人
	genIDFn       func() string     // 生成 JWT ID 的函数
}

func NewOptions(expire time.Duration, encryptKey string,
	opts ...option.Option[Options]) Options {
	dOpts := Options{
		Expire:        expire,
		EncryptionKey: encryptKey,
		DecryptKey:    encryptKey,
		Method:        jwt.SigningMethodHS256,
		genIDFn: func() string {
			return ""
		},
	}
	option.Apply[Options](&dOpts, opts...)
	return dOpts
}

// WithDecryptKey 设置解密密匙
func WithDecryptKey(decryptKey string) option.Option[Options] {
	return func(o *Options) {
		o.DecryptKey = decryptKey
	}
}

// WithMethod 设置 JWT 签名方式
func WithMethod(method jwt.SigningMethod) option.Option[Options] {
	return func(o *Options) {
		o.Method = method
	}
}

// WithIssuer 设置签发人
func WithIssuer(issuer string) option.Option[Options] {
	return func(o *Options) {
		o.Issuer = issuer
	}
}

// WithGenIDFunc 设置生成 JWT ID 函数
func WithGenIDFunc(fn func() string) option.Option[Options] {
	return func(o *Options) {
		o.genIDFn = fn
	}
}
