package alg

import "testing"

func TestKDFParamsBounds(t *testing.T) {
	salt := make([]byte, DefaultSaltLen)

	cases := []struct {
		name string
		p    KDFParams
	}{
		{"argon2 all zero", KDFParams{ID: KDFIDArgon2id, M: 0, T: 0, P: 0, Salt: salt}},
		{"argon2 memory too low", KDFParams{ID: KDFIDArgon2id, M: 1, T: 3, P: 2, Salt: salt}},
		{"argon2 memory too high", KDFParams{ID: KDFIDArgon2id, M: 4096, T: 3, P: 2, Salt: salt}},
		{"argon2 time zero", KDFParams{ID: KDFIDArgon2id, M: 128, T: 0, P: 2, Salt: salt}},
		{"argon2 time too high", KDFParams{ID: KDFIDArgon2id, M: 128, T: 11, P: 2, Salt: salt}},
		{"argon2 parallelism zero", KDFParams{ID: KDFIDArgon2id, M: 128, T: 3, P: 0, Salt: salt}},
		{"pbkdf2 iterations zero", KDFParams{ID: KDFIDPBKDF2, M: 0, Salt: salt}},
		{"pbkdf2 iterations too high", KDFParams{ID: KDFIDPBKDF2, M: MaxPBKDF2Iter + 1, Salt: salt}},
		{"unknown kdf id", KDFParams{ID: 0x7f, M: 128, T: 3, P: 2, Salt: salt}},
		{"empty salt", KDFParams{ID: KDFIDPBKDF2, M: 600_000}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Must return an error, never panic (argon2 panics on invalid params).
			if _, err := c.p.Derive("pass", DefaultKeyLen); err == nil {
				t.Errorf("Derive() = nil error, want rejection")
			}
		})
	}
}
