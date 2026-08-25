package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// TestTheCommittedMarkIsWhatThisGeneratorProduces fails when a generated file has drifted from this
// program.
//
// The mark is committed in four files because four consumers cannot share one, and every way of
// keeping copies in step by hand eventually fails silently: somebody opens the SVG in an editor, nudges
// a curve, and the favicon in the browser tab is a different shape from the one in the toolbar for a
// year. This test is the whole reason the geometry can live in constants rather than in a design file
// nobody in the repository can open.
func TestTheCommittedMarkIsWhatThisGeneratorProduces(t *testing.T) {
	for _, out := range outputs {
		committed, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(out.path)))
		if err != nil {
			t.Errorf("%s: %v — run `make brand`", out.path, err)
			continue
		}
		if !bytes.Equal(committed, out.content()) {
			t.Errorf("%s differs from what this generator produces; edit the constants here and run "+
				"`make brand` rather than editing the file", out.path)
		}
	}
}

// TestTheIconDeclaresEveryImageWhereItActuallyIs parses the .ico back the way a browser does.
//
// An icon file is a directory of offsets and lengths that nothing validates while it is being written:
// a wrong one produces a file that opens fine in the tool that wrote it and shows a blank tab
// everywhere else. Reading it back is the only check that the arithmetic in ico was right.
func TestTheIconDeclaresEveryImageWhereItActuallyIs(t *testing.T) {
	raw := ico()
	if got := binary.LittleEndian.Uint16(raw[2:]); got != 1 {
		t.Fatalf("the file claims type %d rather than 1 (icon)", got)
	}
	count := int(binary.LittleEndian.Uint16(raw[4:]))
	if count != len(iconSizes) {
		t.Fatalf("the directory holds %d images, want %d", count, len(iconSizes))
	}

	for i, size := range iconSizes {
		entry := raw[6+16*i:]
		if entry[0] != size || entry[1] != size {
			t.Errorf("entry %d says %dx%d, want %dx%d", i, entry[0], entry[1], size, size)
		}
		length := int(binary.LittleEndian.Uint32(entry[8:]))
		offset := int(binary.LittleEndian.Uint32(entry[12:]))
		if offset+length > len(raw) {
			t.Fatalf("entry %d points at bytes %d..%d of a %d-byte file", i, offset, offset+length,
				len(raw))
		}
		// 40 bytes of header, four per pixel, and the AND mask the doubled height promises.
		side := int(size)
		want := 40 + 4*side*side + ((side+31)/32)*4*side
		if length != want {
			t.Errorf("entry %d is %d bytes, want %d", i, length, want)
		}
		if got := int(binary.LittleEndian.Uint32(raw[offset:])); got != 40 {
			t.Errorf("image %d starts with a %d-byte header, want 40", i, got)
		}
	}
}

// TestTheSmallestIconLeavesTheNailHolesOut pins the one place the outputs deliberately disagree.
//
// Below nailHoleFloor a hole is about a pixel across, which reads as a speck of dirt rather than as a
// nail hole, so the small icon is drawn without them. That is a decision worth a test rather than a
// comment: it looks exactly like a bug in the hole geometry to whoever finds it next.
func TestTheSmallestIconLeavesTheNailHolesOut(t *testing.T) {
	hole := nailCentres()[0]

	for _, tc := range []struct {
		// size is the icon this checks.
		size uint8

		// wantHole is whether the pixel over a nail hole should be empty.
		wantHole bool
	}{{16, false}, {48, true}} {
		scale := float64(tc.size) / canvas
		column, row := int(hole[0]*scale), int(hole[1]*scale)
		covered := coverage(column, row, tc.size)
		if tc.wantHole && covered != 0 {
			t.Errorf("at %d pixels the nail hole is %.2f covered, want a hole", tc.size, covered)
		}
		if !tc.wantHole && covered != 1 {
			t.Errorf("at %d pixels the pixel over a nail hole is %.2f covered, want solid metal",
				tc.size, covered)
		}
	}
}
