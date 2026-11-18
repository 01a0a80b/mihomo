package shadowlemonwire

// IncrementNonce adds one to a 24-byte big-endian nonce in place, wrapping at
// 2^192. A nil or shorter slice is left unchanged.
func IncrementNonce(nonce []byte) {
	if len(nonce) != NonceLen {
		return
	}
	for i := len(nonce) - 1; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

// PayloadNonce copies the metadata nonce and flips byte 16 with 0x01 to derive
// the payload nonce (spec §4.2). It returns nil if the input is not 24 bytes.
func PayloadNonce(metaNonce []byte) []byte {
	if len(metaNonce) != NonceLen {
		return nil
	}
	out := make([]byte, NonceLen)
	copy(out, metaNonce)
	out[PayloadNonceIndex] ^= PayloadNonceMask
	return out
}
