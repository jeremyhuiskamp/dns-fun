package dns

import (
	"fmt"
	"strings"
)

// NameCompressor keeps track of which names have been
// written at which offsets in a message.
type NameCompressor struct {
	root *recordedLabel
}

func NewNameCompressor() NameCompressor {
	return NameCompressor{
		root: &recordedLabel{},
	}
}

type recordedLabel struct {
	label    Label
	offset   uint16
	children []*recordedLabel
}

func (rn recordedLabel) findChild(label Label) *recordedLabel {
	// Looping and comparing isn't efficient, but for the smallish amount of
	// data in one dns message, it's generally faster and allocates less
	// than using maps.
	for i, child := range rn.children {
		if child.label == label {
			return rn.children[i]
		}
	}
	return nil
}

func (rn *recordedLabel) record(newLabels []Label, offset uint16) {
	for i := len(newLabels) - 1; i >= 0; i-- {
		label := newLabels[i]
		rn.children = append(rn.children, &recordedLabel{
			label:  label,
			offset: offsetAfter(offset, newLabels[:i]),
		})
		rn = rn.children[len(rn.children)-1]
	}
}

func offsetAfter(base uint16, labels []Label) uint16 {
	runningOffset := base
	for _, label := range labels {
		runningOffset += uint16(len(label) + 1)
	}
	return runningOffset
}

func (rn recordedLabel) printTo(buf *strings.Builder, indent int) {
	fmt.Fprintf(buf, "% *s%s@%d\n", indent, "", rn.label, rn.offset)
	for _, child := range rn.children {
		child.printTo(buf, indent+2)
	}
}

// Compress finds a suffix of the name that has already been
// written and returns the prefix that has not yet been written,
// if any, as well as the location where the suffix is.  If
// no suffix has been written, the location is 0 (which is not
// a valid location for a name in a DNS message).
//
// If any prefix of the name hasn't yet been written the compressor
// remembers that it will be written at the given offset.
func (nc NameCompressor) Compress(offset uint16, name Name) ([]Label, uint16) {
	parent := nc.root
	for i := len(name) - 1; i >= 0; i-- {
		child := parent.findChild(name[i])
		if child == nil {
			prefix := name[:i+1]
			parent.record(prefix, offset)
			return prefix, parent.offset
		}
		parent = child
	}
	return nil, parent.offset
}

func (nc NameCompressor) String() string {
	var buf strings.Builder
	nc.root.printTo(&buf, 0)
	return buf.String()
}
