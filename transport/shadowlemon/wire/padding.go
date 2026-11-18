package shadowlemonwire

import "fmt"

// ChoosePadding chooses a padding length in the inclusive range [min, max],
// mirroring the Rust PaddingRange::choose / Go reference choosePaddingLength
// rule: when min >= max and max > 0 it returns max-1 to avoid a fixed-length
// traffic fingerprint; max == 0 returns 0. Otherwise the result is
// min + randBelow(max-min+1), where randBelow must return a value in [0,n).
// randBelow is clamped defensively so a broken RNG cannot produce an
// out-of-range length.
func ChoosePadding(min, max int, randBelow func(n int) int) (int, error) {
	if min < 0 || max < 0 || min > max || max > 255 {
		return 0, fmt.Errorf("%w: min=%d max=%d", ErrInvalidPaddingRange, min, max)
	}
	if max == 0 {
		return 0, nil
	}
	if min >= max {
		return max - 1, nil
	}
	span := max - min + 1
	offset := randBelow(span)
	if offset < 0 {
		offset = 0
	} else if offset >= span {
		offset = span - 1
	}
	return min + offset, nil
}
