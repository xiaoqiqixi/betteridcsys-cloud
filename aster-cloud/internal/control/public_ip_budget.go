package control

import "encoding/json"

const publicIPPageBytes = 1 << 20
const publicIPProjectionBytes = 1792 << 10

// Reserve enough room for the response envelope, comma and cursor. A size cut
// always returns the last actual item as next_cursor, never a skipped row.
func publicIPBudgetPage[T any](items []T, identity func(T) string) ([]T, string, error) {
	size, count := 2, 0
	for count < len(items) && count < 100 {
		raw, err := json.Marshal(items[count])
		if err != nil {
			return nil, "", ErrState
		}
		n := len(raw)
		if count > 0 {
			n++
		}
		if size+n > publicIPPageBytes-256 {
			break
		}
		size += n
		count++
	}
	if count == 0 && len(items) > 0 {
		return nil, "", ErrCapacity
	}
	next := ""
	if count < len(items) {
		next = identity(items[count-1])
	}
	return items[:count], next, nil
}
func publicIPProjectionFits(value any) bool {
	raw, err := json.Marshal(value)
	return err == nil && len(raw) <= publicIPProjectionBytes
}
