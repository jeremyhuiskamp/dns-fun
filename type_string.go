// Code generated by "stringer -type=Type"; DO NOT EDIT.

package dns

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[Query-0]
	_ = x[Response-1]
}

const _Type_name = "QueryResponse"

var _Type_index = [...]uint8{0, 5, 13}

func (i Type) String() string {
	if i >= Type(len(_Type_index)-1) {
		return "Type(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _Type_name[_Type_index[i]:_Type_index[i+1]]
}
