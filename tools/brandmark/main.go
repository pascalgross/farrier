// Command brandmark generates Farrier's mark — a horseshoe — from one description of its geometry.
//
// It exists because the same shape has to appear in four places that cannot share a file: the master
// SVG, a copy the Angular application can serve, a copy the documentation site embeds, and a Windows
// icon the browser tab wants. Drawing it once in an editor and exporting four times is how a mark ends
// up subtly different in each of them, months apart, with nobody able to say which is right. Here the
// geometry is a dozen constants, every output is derived from them, and TestTheCommittedMarkIsWhatThis
// GeneratorProduces fails when a committed file stops matching — so an edit to the shape is an edit to
// this file, and an edit to a generated file is caught.
//
// It draws the raster itself rather than rasterising the SVG, because a renderer that could do that is
// a dependency this repository does not otherwise need. The shape is an annulus with a wedge taken out
// of the bottom and six circles punched through it; the inside test for one point is four lines of
// arithmetic, and supersampling it gives the antialiasing.
//
// Usage:
//
//	brandmark [-root .]
//
// The files it writes are listed in outputs, and every one of them is committed rather than built.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The mark, in the 64-unit square its viewBox describes.
//
// Numbers rather than a drawing, and this is the whole of it. The centre of the arcs is not the centre
// of the square: the toe reaches a full radius above it and the heels only reach the sine of their own
// angle below, so the centre is pushed up until what the box holds is centred — the shape, rather than
// the circle it was cut from.
const (
	// canvas is the side of the square the mark is drawn in, and its viewBox.
	canvas = 64.0

	// centreX and centreY are the centre of the arcs, not of the shape.
	centreX = 32.0
	centreY = 35.5

	// outerRadius takes the mark to within two units of the left and right edges.
	outerRadius = 30.0

	// limbWidth is the metal, and it is heavy on purpose: a thin shoe disappears at 16 pixels.
	limbWidth = 12.0

	// gapHalfAngle is measured from straight down, so the heels sit at 90° ± this and the opening
	// spans twice it. Eighty degrees of daylight is a horseshoe; forty is a broken ring, and a hundred is a letter C.
	gapHalfAngle = 40.0

	// nailRadius is one nail hole.
	nailRadius = 2.0

	// nailHoleFloor is the pixel size below which the holes are left out.
	//
	// At sixteen pixels a hole is one pixel across and reads as dirt on the screen rather than as a
	// nail hole, so the small icon is a plain shoe. That is hinting, and it is the one place where the
	// outputs deliberately differ from each other.
	nailHoleFloor = 24
)

// The mark's one tone, as the three channels the icon writes and the SVG spells out.
//
// It sits between the documentation site's two accents, and that is the whole reason for its value: a
// favicon is drawn on a tab background the page does not choose, so it has to hold up on both. The
// site's light accent disappears against a dark tab strip and its dark accent washes out against a
// light one. This is dark enough on white and light enough on near-black.
const (
	markRed   = 0xb5
	markGreen = 0x71
	markBlue  = 0x39
)

// nailAngles are the nail holes, in degrees from the toe, mirrored onto both branches.
//
// Three a side, which is what a light shoe carries, and spaced widely enough that at 32 pixels they
// read as three holes rather than as a dashed line.
var nailAngles = []float64{55, 85, 115}

// iconSizes are the images inside the .ico, in pixels.
//
// The three Windows and every browser actually ask for. 256 is omitted: nothing displays a favicon that
// large, and it would be four fifths of the file. They are bytes because that is what an icon's
// directory entry holds, and carrying the type from here means nothing has to be narrowed later.
var iconSizes = []uint8{16, 32, 48}

// outputs are the generated files, relative to the repository root, and what each is for.
//
// A table rather than four calls, so that adding a place the mark appears is one line and so that the
// test has a list to walk rather than a list to keep in step with by hand.
var outputs = []struct {
	// path is the file, relative to the repository root.
	path string

	// content produces the bytes it should hold.
	content func() []byte
}{
	// The master, and what the README shows.
	{"brand/farrier-mark.svg", svg},

	// The copy the Angular application serves; nothing outside web/public reaches the browser.
	{"web/public/mark.svg", svg},

	// The documentation site's favicon, embedded by tools/docsite and written into public/.
	{"tools/docsite/favicon.svg", svg},

	// The browser tab of the control plane's own interface.
	{"web/public/favicon.ico", ico},
}

// main writes every generated file.
func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()

	for _, out := range outputs {
		path := filepath.Join(*root, filepath.FromSlash(out.path))
		if err := os.WriteFile(path, out.content(), 0o644); err != nil { //nolint:gosec // G306: published artwork.
			fmt.Fprintf(os.Stderr, "brandmark: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("brandmark: wrote %s\n", out.path)
	}
}

// svg renders the mark as an SVG document.
//
// One path with fill-rule="evenodd", so the nail holes are subpaths rather than a second element in a
// second colour: an <img> of this file over any background shows the background through the holes,
// which is what a hole is.
//
// It carries the tone rather than currentColor, because every consumer today loads it with <img> —
// GitHub, the toolbar, a browser tab — and an <img> gives the file no colour to inherit. Inlining it in
// a component that should follow the surrounding text is a matter of swapping that one fill, and this
// program would be the wrong place to keep a variant nothing uses.
//
// The width and height match the viewBox so that an <img> with no dimensions of its own renders the
// mark at 64 pixels rather than at whatever the container suggests, which is what Markdown's image
// syntax produces.
func svg() []byte {
	var b strings.Builder
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64" `)
	b.WriteString(`role="img" aria-label="Farrier">` + "\n")
	b.WriteString(`  <title>Farrier</title>` + "\n")
	b.WriteString(`  <path fill="` + markColour() + `" fill-rule="evenodd" d="`)
	b.WriteString(outline())
	for _, hole := range nailCentres() {
		b.WriteString(" " + circle(hole[0], hole[1], nailRadius))
	}
	b.WriteString(`"/>` + "\n")
	b.WriteString(`</svg>` + "\n")
	return []byte(b.String())
}

// outline is the shoe itself: the outer arc, a heel, the inner arc back, the other heel.
//
// Both arcs are large-arc, and their sweep flags differ because the second one comes back the way the
// first went out. The heels are the two straight segments between them, radial cuts rather than
// horizontal ones, which is how a shoe is actually cut off.
func outline() string {
	left, right := 90+gapHalfAngle, 90-gapHalfAngle
	inner := outerRadius - limbWidth

	lox, loy := polar(left, outerRadius)
	rox, roy := polar(right, outerRadius)
	rix, riy := polar(right, inner)
	lix, liy := polar(left, inner)

	return fmt.Sprintf("M%s %sA%s %s 0 1 1 %s %sL%s %sA%s %s 0 1 0 %s %sZ",
		num(lox), num(loy),
		num(outerRadius), num(outerRadius), num(rox), num(roy),
		num(rix), num(riy),
		num(inner), num(inner), num(lix), num(liy))
}

// circle renders one nail hole as two half-arcs, which is how a closed circle is written in path data.
func circle(x, y, r float64) string {
	return fmt.Sprintf("M%s %sa%s %s 0 1 0 %s 0a%s %s 0 1 0 -%s 0Z",
		num(x-r), num(y), num(r), num(r), num(2*r), num(r), num(r), num(2*r))
}

// nailCentres are the six nail holes, in canvas coordinates.
//
// Mirrored around the toe rather than listed twice, because a mark whose left and right sides could
// drift apart in a text editor is a mark that eventually does.
func nailCentres() [][2]float64 {
	mid := outerRadius - limbWidth/2
	centres := make([][2]float64, 0, 2*len(nailAngles))
	for _, from := range nailAngles {
		for _, angle := range []float64{270 - from, 270 + from} {
			x, y := polar(angle, mid)
			centres = append(centres, [2]float64{x, y})
		}
	}
	return centres
}

// polar converts an angle in degrees and a radius into canvas coordinates.
//
// Angles are measured the way SVG and the rasteriser both see them — clockwise from the positive x
// axis, because y grows downwards — so straight down is 90° and the toe is at 270°.
func polar(degrees, radius float64) (float64, float64) {
	radians := degrees * math.Pi / 180
	return centreX + radius*math.Cos(radians), centreY + radius*math.Sin(radians)
}

// inside reports whether a point in canvas coordinates is metal.
//
// The whole shape, in one predicate: between the two radii, outside the wedge at the bottom, and not in
// a nail hole. The SVG says the same thing in a path and this says it in arithmetic; they agree because
// they are the same constants, and the test is what keeps that true.
func inside(x, y float64, withHoles bool) bool {
	dx, dy := x-centreX, y-centreY
	distance := math.Hypot(dx, dy)
	if distance < outerRadius-limbWidth || distance > outerRadius {
		return false
	}

	degrees := math.Atan2(dy, dx) * 180 / math.Pi
	if degrees < 0 {
		degrees += 360
	}
	if degrees > 90-gapHalfAngle && degrees < 90+gapHalfAngle {
		return false
	}

	if withHoles {
		for _, hole := range nailCentres() {
			if math.Hypot(x-hole[0], y-hole[1]) <= nailRadius {
				return false
			}
		}
	}
	return true
}

// samples is the supersampling grid used per pixel, one side of it.
//
// Six by six: thirty-six coverage values per pixel, which is enough that the outer arc has no visible
// stair-stepping at 16 pixels and cheap enough that the whole icon renders in a millisecond.
const samples = 6

// ico renders the mark into a Windows icon holding one image per size.
func ico() []byte {
	images := make([][]byte, len(iconSizes))
	for i, size := range iconSizes {
		images[i] = icon(size)
	}

	var buf bytes.Buffer
	write := func(values ...any) {
		for _, v := range values {
			_ = binary.Write(&buf, binary.LittleEndian, v)
		}
	}
	// ICONDIR: reserved, type 1 (icon), count.
	write(uint16(0), uint16(1), uint16(len(images))) //nolint:gosec // G115: three images, counted here.

	offset := 6 + 16*len(images)
	for i, size := range iconSizes {
		// ICONDIRENTRY. The colour count and the planes are zero and one for a true-colour image, and
		// the sizes are single bytes — which is why 256 would have to be written as 0 and why it is not
		// here.
		//
		//nolint:gosec // G115: the whole file is a few kilobytes, so no length or offset in it is
		// anywhere near 2^32 — and the format has no wider field to put one in.
		write(size, size, uint8(0), uint8(0), uint16(1), uint16(32),
			uint32(len(images[i])), uint32(offset))
		offset += len(images[i])
	}
	for _, image := range images {
		buf.Write(image)
	}
	return buf.Bytes()
}

// icon renders one size as the DIB an .ico entry holds.
//
// A bottom-up 32-bit bitmap whose header claims twice its height, followed by the 1-bit AND mask that
// height is claiming space for. The mask is all zeros — the alpha channel is what actually shapes the
// icon — but it is not optional: readers seek past it to find the next image, and an icon without one
// is an icon whose second image is garbage.
func icon(size uint8) []byte {
	var buf bytes.Buffer
	write := func(values ...any) {
		for _, v := range values {
			_ = binary.Write(&buf, binary.LittleEndian, v)
		}
	}
	// BITMAPINFOHEADER: size, width, height (doubled), planes, bits, compression, image size, four
	// fields nothing reads for an icon.
	write(uint32(40), int32(size), 2*int32(size), uint16(1), uint16(32), uint32(0),
		4*uint32(size)*uint32(size), int32(0), int32(0), uint32(0), uint32(0))

	side := int(size)
	for row := side - 1; row >= 0; row-- {
		for column := 0; column < side; column++ {
			alpha := coverage(column, row, size)
			write(uint8(markBlue), uint8(markGreen), uint8(markRed), uint8(math.Round(alpha*255)))
		}
	}

	// The AND mask: one bit per pixel, each row padded to four bytes.
	stride := ((side + 31) / 32) * 4
	buf.Write(make([]byte, stride*side))
	return buf.Bytes()
}

// coverage is how much of one pixel the mark covers, from 0 to 1.
//
// Coverage rather than a yes or no, because the alternative at these sizes is a shoe with a serrated
// edge. The samples are offset by half a step so that they sit in the middle of their own cells rather
// than on the pixel's boundary, where a shape aligned to the grid would be counted twice or not at all.
func coverage(column, row int, size uint8) float64 {
	scale := canvas / float64(size)
	withHoles := int(size) >= nailHoleFloor

	hits := 0
	for sy := 0; sy < samples; sy++ {
		for sx := 0; sx < samples; sx++ {
			x := (float64(column) + (float64(sx)+0.5)/samples) * scale
			y := (float64(row) + (float64(sy)+0.5)/samples) * scale
			if inside(x, y, withHoles) {
				hits++
			}
		}
	}
	return float64(hits) / float64(samples*samples)
}

// markColour renders the tone as the hex string an SVG fill wants.
//
// Derived from the three constants rather than written out beside them, so that the icon and the SVG
// cannot end up in two different browns.
func markColour() string {
	return fmt.Sprintf("#%02x%02x%02x", markRed, markGreen, markBlue)
}

// num formats a coordinate for path data: three decimals, and no trailing zeros to carry them.
func num(value float64) string {
	text := strconv.FormatFloat(value, 'f', 3, 64)
	text = strings.TrimRight(text, "0")
	return strings.TrimSuffix(text, ".")
}
