package dns

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
	for _, child := range rn.children {
		if child.label == label {
			return child
		}
	}
	return nil
}

// Record that the given name was written at the given offset.
func (nc *NameCompressor) Record(offset uint16, name Name) {
	offsets := matchingOffsets(offset, name)

	addToTree(nc.root, name, offsets)
}

func matchingOffsets(offset uint16, name Name) []uint16 {
	offsets := make([]uint16, len(name))
	runningOffset := offset
	for i, label := range name {
		offsets[i] = runningOffset
		runningOffset += uint16(len(label) + 1)
	}
	return offsets
}

func addToTree(parent *recordedLabel, name Name, offsets []uint16) {
	for i := len(name) - 1; i >= 0; i-- {
		label := name[i]

		matchingChild := parent.findChild(label)
		if matchingChild == nil {
			matchingChild = &recordedLabel{
				label:  label,
				offset: offsets[i],
			}
			parent.children = append(parent.children, matchingChild)
		}

		// NB: ignore the new offset if there was already
		// a matching child.  The new offset is probably not
		// valid because the caller will have already
		// referenced the matching prefix.

		parent = matchingChild
	}
}

// Lookup where a name might have been previously recorded.
//
// Returns (skip, offset)
//
// If the exact name hasn't been recorded, but a parent has,
// the offset of the parent is returned, and the number of
// name components before the parent is returned as `skip`,
// indicating that that many components should be written
// before referencing the parent.
//
// The offset 0 means that the name has never been written
// (no names may occur in the first 12 bytes of a message).
func (nc NameCompressor) Lookup(name Name) (int, uint16) {
	parent := nc.root
	for i := len(name) - 1; i >= 0; i-- {
		label := name[i]
		child := parent.findChild(label)
		if child == nil {

			// i corresponds to the child, i+1 to the parent
			return i + 1, parent.offset
		}
		parent = child
	}
	return 0, parent.offset
}
