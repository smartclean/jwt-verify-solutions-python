VALID_JWK_OBJECT_1 = {
            "kid": "1234example=",
            "alg": "RS256",
            "kty": "RSA",
            "e": "AQAB",
            "n": "1234567890",
            "use": "sig"
        }
INVALID_JWK_OBJECT_1 = {
            "kid": "5678example=",
            "alg": "RS256",
            "kty": "RSA",
            "e": "AQAB",
            "n": "987654321",
            "use": "sig"
        }

TEST_JWKS_DATA = {
    "keys": [
        VALID_JWK_OBJECT_1,
        INVALID_JWK_OBJECT_1
    ]
}

PUBLIC_KEY_FOR_VALID_JWK_OBJECT_1 = '-----BEGIN PUBLIC KEY-----\nMCMwDQYJKoZIhvcNAQEBBQADEgAwDwIIANdt+Oeu/PcCAwEAAQ==' \
                                    '\n-----END PUBLIC KEY-----\n'
