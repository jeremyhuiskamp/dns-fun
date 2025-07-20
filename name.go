package dns

import (
	"errors"
	"strings"
)

type Label string

// TODO:
// - Name.Validate() -> return err if not valid
// - Name.String() -> pretty obvious!
// - NameOf() -> convenience constructor? should it validate? needs better name...
//   - maybe it should validate and panic, for convenience...
//
// - consider canonicalising to lower-case?
type Name []Label

var ErrEmtyLabel = errors.New("no label may be empty")
var ErrLabelTooLong = errors.New("no label may be longer than 63 bytes")
var ErrNameTooLong = errors.New("a name may not exceed 255 bytes")

func ParseName(hostname string) (Name, error) {
	labels := strings.Split(hostname, ".")
	name := make(Name, len(labels))
	totalLen := 0
	for i, label := range labels {
		if label == "" {
			if i == len(labels)-1 {
				// trim trailing '.'
				name = name[:i]
				break
			}
			return nil, ErrEmtyLabel
		} else if len(label) > 63 {
			return nil, ErrLabelTooLong
		}
		name[i] = Label(label)
		totalLen += len(label) + 1
		// max length is 255, but we need one more byte for the root
		if totalLen > 254 {
			return nil, ErrNameTooLong
		}
	}
	return name, nil
}

func (n Name) Equal(other Name) bool {
	if len(n) != len(other) {
		return false
	}
	for i, label := range n {
		if !strings.EqualFold(string(label), string(other[i])) {
			return false
		}
	}
	return true
}

func (n Name) IsParentOf(other Name) bool {
	if len(other) <= len(n) {
		return false
	}
	return other[len(other)-len(n):].Equal(n)
}

func (n Name) IsSubdomainOf(other Name) bool {
	return other.IsParentOf(n)
}

func (n Name) String() string {
	// adapted from strings.Join
	switch len(n) {
	case 0:
		return ""
	case 1:
		return string(n[0])
	}

	var l int
	for _, label := range n {
		l += len(label)
	}

	var b strings.Builder
	b.Grow(l)
	b.WriteString(string(n[0]))
	for _, label := range n[1:] {
		b.WriteString(".")
		b.WriteString(string(label))
	}
	return b.String()
}
