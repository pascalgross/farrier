// Command brandmark generates HostSeal's mark — an impressed seal — from one description of its
// geometry.
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
// a dependency this repository does not otherwise need. The shape is a disc whose edge is a ring of
// scallops — the pressed rim of a wax seal — with one groove impressed into its face; the inside test
// for one point is four lines of arithmetic, and supersampling it gives the antialiasing.
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
// Numbers rather than a drawing, and this is the whole of it. The shape is radially symmetric, so the
// centre of every arc is the centre of the square and no constant here is a correction for anything.
const (
	// canvas is the side of the square the mark is drawn in, and its viewBox.
	canvas = 64.0

	// centreX and centreY are the centre of every arc in the mark.
	centreX = 32.0
	centreY = 32.0

	// rimRadius is where a scallop peaks, which takes the mark to within two units of every edge.
	rimRadius = 30.0

	// scallops is how many bumps the rim carries.
	//
	// Fourteen, because the count and the depth trade against each other and this is where both land:
	// few and deep is a flower, many and shallow is a plain disc with a rough edge. Fourteen shallow
	// bumps read as something that was pressed.
	scallops = 14

	// scallopRadius is one bump.
	//
	// Adjacent bumps have to overlap or the rim is a ring of separate circles, which needs this to
	// exceed scallopCentreRadius·sin(halfStep) — under five units here. Well over that minimum on
	// purpose: near it each bump is most of its own circle and the mark is a flower, and at 8.5 a bump
	// is a hundred degrees of arc and the rim swings two and a half units, which is a scallop.
	scallopRadius = 8.5

	// scallopCentreRadius puts the bumps where their peaks land exactly on the rim.
	scallopCentreRadius = rimRadius - scallopRadius

	// grooveInnerRadius and grooveOuterRadius are the ring impressed into the seal's face: the line
	// that separates a seal's border from whatever it was pressed with. It is a void rather than a
	// second colour, so an <img> of the mark shows the page through it.
	grooveInnerRadius = 19.5
	grooveOuterRadius = 22.5

	// grooveFloor is the pixel size below which the groove is left out.
	//
	// At sixteen pixels the groove is one pixel across and reads as dirt on the screen rather than as
	// an impression, so the small icon is a plain scalloped disc. That is hinting, and it is the one
	// place where the outputs deliberately differ from each other.
	grooveFloor = 24

	// halfStep is half the angle one scallop occupies, in radians, and it appears in enough of the
	// geometry to be worth naming once.
	halfStep = math.Pi / scallops
)

// valleyRadius is how far the rim dips between two scallops, and with it the radius of the plain disc
// the scallops sit on.
//
// Where two neighbouring bumps cross. Both have radius scallopRadius and their centres are
// 2·scallopCentreRadius·sin(halfStep) apart, so the crossing sits on the bisector between them, at
// scallopCentreRadius·cos(halfStep) plus the half-chord the circles leave. Derived rather than written
// down because it has to agree with the three constants above exactly: the SVG puts the ends of its
// arcs here and the rasteriser draws its disc out to here, and a hand-rounded value would show up as a
// hairline where the two disagree.
var valleyRadius = scallopCentreRadius*math.Cos(halfStep) +
	math.Sqrt(scallopRadius*scallopRadius-
		math.Pow(scallopCentreRadius*math.Sin(halfStep), 2))

// The mark's one tone, as the three channels the icon writes and the SVG spells out.
//
// It sits between the documentation site's two accents, and that is the whole reason for its value: a
// favicon is drawn on a tab background the page does not choose, so it has to hold up on both. The
// site's light accent disappears against a dark tab strip and its dark accent washes out against a
// light one. This is dark enough on white and light enough on near-black. That it also happens to be
// the colour of sealing wax is a coincidence the mark is welcome to keep.
const (
	markRed   = 0xb5
	markGreen = 0x71
	markBlue  = 0x39
)

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
	{"brand/hostseal-mark.svg", svg},

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
// One path with fill-rule="evenodd", so the groove is a pair of subpaths rather than a second element
// in a second colour: an <img> of this file over any background shows the background through it, which
// is what an impression looks like. The two circles are why the rule has to be evenodd — the outer one
// cuts the void and the inner one fills the boss back in, and under the default winding rule the second
// would do nothing.
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
	b.WriteString(`role="img" aria-label="HostSeal">` + "\n")
	b.WriteString(`  <title>HostSeal</title>` + "\n")
	b.WriteString(`  <path fill="` + markColour() + `" fill-rule="evenodd" d="`)
	b.WriteString(outline())
	b.WriteString(" " + circle(centreX, centreY, grooveOuterRadius))
	b.WriteString(" " + circle(centreX, centreY, grooveInnerRadius))
	b.WriteString(`"/>` + "\n")
	b.WriteString(`</svg>` + "\n")
	return []byte(b.String())
}

// outline is the seal's edge: one arc per scallop, each bulging outward between two valleys.
//
// Every arc is a piece of its own scallop circle, so the radius written into the path is
// scallopRadius rather than anything to do with the rim. None of them is a large arc — a scallop is
// under half of its circle, which is what keeps the rim a rim rather than a ring of lollipops — and
// every sweep flag is 1 because the path walks the edge in the direction of increasing angle, which in
// a coordinate system whose y grows downwards is the positive one.
func outline() string {
	step := 360.0 / scallops

	var b strings.Builder
	x, y := polar(step/2, valleyRadius)
	fmt.Fprintf(&b, "M%s %s", num(x), num(y))
	for scallop := 1; scallop <= scallops; scallop++ {
		x, y = polar(step/2+step*float64(scallop), valleyRadius)
		fmt.Fprintf(&b, "A%s %s 0 0 1 %s %s",
			num(scallopRadius), num(scallopRadius), num(x), num(y))
	}
	b.WriteString("Z")
	return b.String()
}

// circle renders one circle as two half-arcs, which is how a closed circle is written in path data.
func circle(x, y, r float64) string {
	return fmt.Sprintf("M%s %sa%s %s 0 1 0 %s 0a%s %s 0 1 0 -%s 0Z",
		num(x-r), num(y), num(r), num(r), num(2*r), num(r), num(r), num(2*r))
}

// scallopCentres are the centres of the circles the rim is cut from, in canvas coordinates.
//
// Generated from the count rather than listed, because a mark whose bumps could drift apart in a text
// editor is a mark that eventually does — and because the rasteriser and the SVG have to be looking at
// the same twelve circles or the raster will not match the vector.
func scallopCentres() [][2]float64 {
	step := 360.0 / scallops
	centres := make([][2]float64, 0, scallops)
	for scallop := 0; scallop < scallops; scallop++ {
		x, y := polar(step*float64(scallop), scallopCentreRadius)
		centres = append(centres, [2]float64{x, y})
	}
	return centres
}

// polar converts an angle in degrees and a radius into canvas coordinates.
//
// Angles are measured the way SVG and the rasteriser both see them — clockwise from the positive x
// axis, because y grows downwards — so a scallop sits at every multiple of 30° and a valley halfway
// between two of them.
func polar(degrees, radius float64) (float64, float64) {
	radians := degrees * math.Pi / 180
	return centreX + radius*math.Cos(radians), centreY + radius*math.Sin(radians)
}

// inside reports whether a point in canvas coordinates is wax.
//
// The whole shape, in one predicate: inside the plain disc the scallops sit on, or inside one of the
// scallops, and not in the groove. The SVG says the same thing in a path and this says it in
// arithmetic; they agree because they are the same constants, and the test is what keeps that true.
func inside(x, y float64, withGroove bool) bool {
	distance := math.Hypot(x-centreX, y-centreY)
	if distance > valleyRadius && !inScallop(x, y) {
		return false
	}
	if withGroove && distance > grooveInnerRadius && distance < grooveOuterRadius {
		return false
	}
	return true
}

// inScallop reports whether a point falls inside one of the circles the rim is cut from.
//
// Separate from inside because it is the one part of the predicate that is a loop rather than a
// comparison, and because the shape between valleyRadius and rimRadius is exactly their union — there
// is nothing else out there to test against.
func inScallop(x, y float64) bool {
	for _, centre := range scallopCentres() {
		if math.Hypot(x-centre[0], y-centre[1]) <= scallopRadius {
			return true
		}
	}
	return false
}

// samples is the supersampling grid used per pixel, one side of it.
//
// Six by six: thirty-six coverage values per pixel, which is enough that the scalloped rim has no
// visible stair-stepping at 16 pixels and cheap enough that the whole icon renders in a millisecond.
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
// Coverage rather than a yes or no, because the alternative at these sizes is a rim whose twelve bumps
// are twelve staircases. The samples are offset by half a step so that they sit in the middle of their
// own cells rather than on the pixel's boundary, where a shape aligned to the grid would be counted
// twice or not at all.
func coverage(column, row int, size uint8) float64 {
	scale := canvas / float64(size)
	withGroove := int(size) >= grooveFloor

	hits := 0
	for sy := 0; sy < samples; sy++ {
		for sx := 0; sx < samples; sx++ {
			x := (float64(column) + (float64(sx)+0.5)/samples) * scale
			y := (float64(row) + (float64(sy)+0.5)/samples) * scale
			if inside(x, y, withGroove) {
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
