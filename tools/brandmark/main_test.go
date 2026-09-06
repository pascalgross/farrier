package main

import (
	"bytes"
	"encoding/binary"
	"math"
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

// TestTheSmallestIconLeavesTheGrooveOut pins the one place the outputs deliberately disagree.
//
// Below grooveFloor the groove is about a pixel across, which reads as a speck of dirt rather than as
// an impression, so the small icon is drawn without it. That is a decision worth a test rather than a
// comment: it looks exactly like a bug in the groove geometry to whoever finds it next.
func TestTheSmallestIconLeavesTheGrooveOut(t *testing.T) {
	x, y := polar(0, (grooveInnerRadius+grooveOuterRadius)/2)

	for _, tc := range []struct {
		// size is the icon this checks.
		size uint8

		// wantGroove is whether the pixel over the groove should be empty.
		wantGroove bool
	}{{16, false}, {48, true}} {
		scale := float64(tc.size) / canvas
		column, row := int(x*scale), int(y*scale)
		covered := coverage(column, row, tc.size)
		if tc.wantGroove && covered != 0 {
			t.Errorf("at %d pixels the groove is %.2f covered, want a void", tc.size, covered)
		}
		if !tc.wantGroove && covered != 1 {
			t.Errorf("at %d pixels the pixel over the groove is %.2f covered, want solid wax",
				tc.size, covered)
		}
	}
}

// TestTheRimIsOneContinuousEdge fails if the scallops stop overlapping.
//
// The rim only reads as a pressed edge while neighbouring scallops cross each other; make
// scallopRadius small enough and they separate into twelve circles sitting on a plain disc, which is a
// different mark with a visible seam at every valley. The condition is one inequality, and it is the
// only thing standing between a plausible-looking edit to the constants and a shape nobody meant.
func TestTheRimIsOneContinuousEdge(t *testing.T) {
	if scallopRadius <= scallopCentreRadius*math.Sin(halfStep) {
		t.Fatalf("scallops of radius %g do not reach each other at %g units out: the rim would break "+
			"into %d separate circles", scallopRadius, scallopCentreRadius, scallops)
	}
	if valleyRadius >= rimRadius {
		t.Errorf("the rim dips to %g and peaks at %g, so there is nothing to see", valleyRadius,
			rimRadius)
	}
}
