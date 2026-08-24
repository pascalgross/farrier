package pkcs11

import (
	"context"
	"crypto/ed25519"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/ebitengine/purego"

	"github.com/pascalgross/farrier/internal/signing"
	"github.com/pascalgross/farrier/internal/signing/backend"
)

// The fixture builds its own token out of the module under test, with no vendor tooling at all:
// C_InitToken, C_InitPIN and C_GenerateKeyPair are part of every PKCS#11 module, so a test needs the
// library and nothing else. That matters for CI, where installing libsofthsm2 is one apt line and
// installing a working softhsm2-util plus its configuration is several.

// Fixture identities, used by every test below.
const (
	// testTokenLabel is what the fixture calls its token.
	testTokenLabel = "farrier-test"

	// testSOPIN and testUserPIN are the token's two PINs. A fixture PIN, on a token that lives in a
	// temporary directory for the length of one test binary.
	testSOPIN   = "12345678"
	testUserPIN = "1234"

	// testECLabel and testEdLabel name the two key pairs the fixture generates.
	testECLabel = "ops-token-1"
	testEdLabel = "ops-token-ed"
)

// Extra PKCS#11 constants the fixture needs and the backend does not.
const (
	ckfRWSession                ckULong = 0x02
	ckuSO                       ckULong = 0
	ckaToken                    ckULong = 0x01
	ckaPrivate                  ckULong = 0x02
	ckaSensitive                ckULong = 0x103
	ckaSign                     ckULong = 0x108
	ckaVerify                   ckULong = 0x10A
	ckmECKeyPairGen             ckULong = 0x1040
	ckmECEdwardsKeyPairGen      ckULong = 0x1055
	fnInitToken                 int     = 9
	fnInitPIN                   int     = 10
	fnGenerateKeyPair           int     = 59
	fixtureTokenInfoLabelPadded         = 32
)

// fixture is the token every test in this package signs against.
//
// One token for the whole binary rather than one per test. SoftHSM reads SOFTHSM2_CONF when a module
// is initialised, and a fixture that changed it between tests would be asserting something about the
// module's configuration caching rather than about this backend.
var fixture struct {
	// once guards the build.
	once sync.Once

	// modulePath is the library under test.
	modulePath string

	// err is why the fixture could not be built, if it could not.
	err error

	// skip is set when there is simply no module on this machine.
	skip bool
}

// tokenFixture builds the shared token, or skips the test when no PKCS#11 module is installed.
//
// A named-but-unusable module is a fatal error rather than a skip. That is the same stance the store
// tests take about a database: a skipped test is indistinguishable from a passing one in a summary,
// and FARRIER_TEST_PKCS11_MODULE exists precisely to make a CI misconfiguration visible.
func tokenFixture(t *testing.T) string {
	t.Helper()
	fixture.once.Do(func() { buildFixture() })

	if fixture.skip {
		t.Skip("no PKCS#11 module found; install libsofthsm2, or set FARRIER_TEST_PKCS11_MODULE")
	}
	if fixture.err != nil {
		t.Fatalf("building the token fixture: %v", fixture.err)
	}
	return fixture.modulePath
}

// buildFixture locates a module, writes a configuration for it, and generates the two key pairs.
func buildFixture() {
	path, ok := locateModule()
	if !ok {
		fixture.skip = true
		return
	}
	fixture.modulePath = path

	// A directory that outlives every test in the binary, which is what one shared token needs. It is
	// under the OS temporary directory rather than a t.TempDir, because t.TempDir belongs to the test
	// that asked for it and this token belongs to all of them.
	dir, err := os.MkdirTemp("", "farrier-pkcs11-")
	if err != nil {
		fixture.err = err
		return
	}
	config := filepath.Join(dir, "softhsm2.conf")
	body := "directories.tokendir = " + dir + "\nobjectstore.backend = file\nlog.level = ERROR\n"
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		fixture.err = err
		return
	}
	// Set for the process rather than through t.Setenv: the fixture is shared, so its environment has
	// to outlive whichever test happened to build it. purego installs the C setenv shim under
	// CGO_ENABLED=0, so a module reading getenv sees this.
	if err := os.Setenv("SOFTHSM2_CONF", config); err != nil {
		fixture.err = err
		return
	}
	fixture.err = generateFixtureKeys(path)
}

// locateModule finds a PKCS#11 module to test against.
//
// The path is not a constant because the point of this backend is that no vendor is hard-coded, and
// the module sits in a different place on every distribution and for every token.
func locateModule() (string, bool) {
	if named := os.Getenv("FARRIER_TEST_PKCS11_MODULE"); named != "" {
		return named, true
	}
	for _, candidate := range []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, true
		}
	}
	return "", false
}

// fixtureModule is the extra slice of the C ABI the fixture drives, beyond what the backend binds.
type fixtureModule struct {
	// module carries the entry points the backend already binds.
	*module

	// initToken, initPIN and generateKeyPair build a token from nothing.
	initToken       func(slot ckULong, pin unsafe.Pointer, pinLen ckULong, label unsafe.Pointer) ckReturn
	initPIN         func(session ckULong, pin unsafe.Pointer, pinLen ckULong) ckReturn
	generateKeyPair func(session ckULong, mechanism unsafe.Pointer,
		publicTemplate unsafe.Pointer, publicCount ckULong,
		privateTemplate unsafe.Pointer, privateCount ckULong,
		publicKey, privateKey unsafe.Pointer) ckReturn
}

// generateFixtureKeys initialises the token and puts one P-256 and one Ed25519 key pair on it.
func generateFixtureKeys(path string) error {
	mod, err := openModule(path)
	if err != nil {
		return err
	}
	defer finalize(mod)

	list, err := fixtureFunctions(mod, path)
	if err != nil {
		return err
	}

	args := ckInitializeArgs{flags: ckfOSLockingOK}
	if err := check("C_Initialize", mod.initialize(pointerTo(&args))); err != nil {
		return err
	}

	slot, err := firstSlot(mod)
	if err != nil {
		return err
	}

	label := make([]byte, fixtureTokenInfoLabelPadded)
	for i := range label {
		label[i] = ' '
	}
	copy(label, testTokenLabel)
	so := []byte(testSOPIN)
	if err := check("C_InitToken", list.initToken(slot, unsafe.Pointer(&so[0]),
		ckULong(len(so)), unsafe.Pointer(&label[0]))); err != nil {
		return err
	}

	// The token is reassigned to a new slot by C_InitToken, so the slot list is read again rather
	// than reused — a fixture that kept the old handle fails on SoftHSM with an invalid slot.
	slot, err = firstSlot(mod)
	if err != nil {
		return err
	}

	var session ckULong
	if err := check("C_OpenSession", mod.openSession(slot, ckfSerialSession|ckfRWSession,
		nil, nil, unsafe.Pointer(&session))); err != nil {
		return err
	}
	defer func() { _ = mod.closeSession(session) }()

	if err := check("C_Login(SO)", mod.login(session, ckuSO,
		unsafe.Pointer(&so[0]), ckULong(len(so)))); err != nil {
		return err
	}
	user := []byte(testUserPIN)
	if err := check("C_InitPIN", list.initPIN(session,
		unsafe.Pointer(&user[0]), ckULong(len(user)))); err != nil {
		return err
	}
	if err := check("C_Logout", mod.logout(session)); err != nil {
		return err
	}
	if err := check("C_Login(user)", mod.login(session, ckuUser,
		unsafe.Pointer(&user[0]), ckULong(len(user)))); err != nil {
		return err
	}

	if err := list.generatePair(session, ckmECKeyPairGen, p256Params, testECLabel, []byte{0x01}); err != nil {
		return fmt.Errorf("generating the P-256 pair: %w", err)
	}
	if err := list.generatePair(session, ckmECEdwardsKeyPairGen, edwards25519Params[1],
		testEdLabel, []byte{0x02}); err != nil {
		return fmt.Errorf("generating the Ed25519 pair: %w", err)
	}
	return nil
}

// fixtureFunctions binds the three extra entry points the fixture needs.
func fixtureFunctions(mod *module, path string) (*fixtureModule, error) {
	handle, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, err
	}
	var getFunctionList func(list unsafe.Pointer) ckReturn
	if err := bind(handle, &getFunctionList, "C_GetFunctionList"); err != nil {
		return nil, err
	}
	var raw *functionList
	if rv := getFunctionList(unsafe.Pointer(&raw)); rv != ckrOK {
		return nil, check("C_GetFunctionList", rv)
	}

	out := &fixtureModule{module: mod}
	purego.RegisterFunc(&out.initToken, raw.fn[fnInitToken])
	purego.RegisterFunc(&out.initPIN, raw.fn[fnInitPIN])
	purego.RegisterFunc(&out.generateKeyPair, raw.fn[fnGenerateKeyPair])
	return out, nil
}

// firstSlot returns the first slot the module reports, token or not.
func firstSlot(mod *module) (ckULong, error) {
	var count ckULong
	if err := check("C_GetSlotList", mod.getSlotList(0, nil, unsafe.Pointer(&count))); err != nil {
		return 0, err
	}
	if count == 0 {
		return 0, errors.New("the module reports no slots at all")
	}
	slots := make([]ckULong, count)
	if err := check("C_GetSlotList",
		mod.getSlotList(0, unsafe.Pointer(&slots[0]), unsafe.Pointer(&count))); err != nil {
		return 0, err
	}
	return slots[0], nil
}

// generatePair creates one key pair on the token, labelled and identified.
func (f *fixtureModule) generatePair(session, mechanism ckULong, params []byte,
	label string, id []byte) error {

	mech := ckMechanism{mechanism: mechanism}
	yes := byte(1)
	labelBytes := []byte(label)
	curve := params

	public := []ckAttribute{
		{kind: ckaToken, value: unsafe.Pointer(&yes), valueLen: 1},
		{kind: ckaVerify, value: unsafe.Pointer(&yes), valueLen: 1},
		{kind: ckaECParams, value: unsafe.Pointer(&curve[0]), valueLen: ckULong(len(curve))},
		{kind: ckaLabel, value: unsafe.Pointer(&labelBytes[0]), valueLen: ckULong(len(labelBytes))},
		{kind: ckaID, value: unsafe.Pointer(&id[0]), valueLen: ckULong(len(id))},
	}
	private := []ckAttribute{
		{kind: ckaToken, value: unsafe.Pointer(&yes), valueLen: 1},
		{kind: ckaPrivate, value: unsafe.Pointer(&yes), valueLen: 1},
		{kind: ckaSensitive, value: unsafe.Pointer(&yes), valueLen: 1},
		{kind: ckaSign, value: unsafe.Pointer(&yes), valueLen: 1},
		{kind: ckaLabel, value: unsafe.Pointer(&labelBytes[0]), valueLen: ckULong(len(labelBytes))},
		{kind: ckaID, value: unsafe.Pointer(&id[0]), valueLen: ckULong(len(id))},
	}

	var pub, priv ckULong
	return check("C_GenerateKeyPair", f.generateKeyPair(session, unsafe.Pointer(&mech),
		unsafe.Pointer(&public[0]), ckULong(len(public)),
		unsafe.Pointer(&private[0]), ckULong(len(private)),
		unsafe.Pointer(&pub), unsafe.Pointer(&priv)))
}

// reference builds a PKCS#11 URI for the fixture token, with the scheme already stripped.
func reference(modulePath, object string) string {
	return "token=" + testTokenLabel + ";object=" + object + "?module-path=" + modulePath
}

// pinPrompt answers with the fixture's user PIN.
func pinPrompt(pin string) backend.PassphraseFunc {
	return func(string) ([]byte, error) { return []byte(pin), nil }
}

// TestTheCTypesAreTheSizeCExpects converts the one silent failure mode into a named one.
//
// purego gives no compiler check on the ABI: a struct one field short shifts every entry point and
// calls C_Finalize where C_Initialize was meant, and the symptom is a crash inside a vendor library
// rather than a build error. These four sizes are the whole of the layout this package asserts, and
// the cost of asserting them is nothing.
func TestTheCTypesAreTheSizeCExpects(t *testing.T) {
	for _, c := range []struct {
		// what names the C type.
		what string

		// got is Go's size for it.
		got uintptr

		// want is what the C ABI lays out on LP64.
		want uintptr
	}{
		{"CK_ATTRIBUTE", unsafe.Sizeof(ckAttribute{}), 24},
		{"CK_MECHANISM", unsafe.Sizeof(ckMechanism{}), 24},
		{"CK_C_INITIALIZE_ARGS", unsafe.Sizeof(ckInitializeArgs{}), 48},
		{"CK_FUNCTION_LIST", unsafe.Sizeof(functionList{}), 8 + fnCount*8},
	} {
		if c.got != c.want {
			t.Errorf("%s is %d bytes in Go and %d in C", c.what, c.got, c.want)
		}
	}
}

// TestSignAndVerifyRoundTrip is the whole path, for both algorithms.
//
// It signs on the token, renders the trusted-signers line an administrator would paste, parses that
// line with the agent's own parser, and verifies with the agent's own verifier. A backend that passed
// every other test in this file and failed this one would produce signatures no host accepts.
func TestSignAndVerifyRoundTrip(t *testing.T) {
	modulePath := tokenFixture(t)

	for _, c := range []struct {
		// object is the key's label on the token.
		object string

		// algorithm is what the backend must resolve it to.
		algorithm signing.Algorithm
	}{
		{testECLabel, signing.ECDSAP256},
		{testEdLabel, signing.Ed25519},
	} {
		t.Run(string(c.algorithm), func(t *testing.T) {
			signer, err := open(context.Background(), reference(modulePath, c.object),
				pinPrompt(testUserPIN))
			if err != nil {
				t.Fatalf("opening the token: %v", err)
			}
			defer func() { _ = signer.Close() }()

			if signer.Algorithm() != c.algorithm {
				t.Fatalf("the backend resolved %s, expected %s", signer.Algorithm(), c.algorithm)
			}
			if signer.KeyID() != c.object {
				t.Errorf("the key id is %q, expected the object label %q", signer.KeyID(), c.object)
			}
			if signer.Backend() != "pkcs11" {
				t.Errorf("the backend reports %q", signer.Backend())
			}

			payload := []byte(`{"hostId":"01JHOST","intent":"host.reboot"}`)
			signature, err := signer.Sign(context.Background(), payload)
			if err != nil {
				t.Fatalf("signing: %v", err)
			}

			line, err := signing.TrustedSignerLine(signer)
			if err != nil {
				t.Fatalf("rendering the trusted-signers line: %v", err)
			}
			set, err := signing.ParseSigners(strings.NewReader(line+"\n"), "test")
			if err != nil {
				t.Fatalf("parsing the line an administrator would paste: %v", err)
			}
			key, err := set.Verify(payload, signature)
			if err != nil {
				t.Fatalf("a host would refuse this signature: %v", err)
			}
			if key.String() != c.object+" (pkcs11)" {
				t.Errorf("the audit log would read %q", key.String())
			}
		})
	}
}

// TestGuaranteeAnECDSASignatureIsDEREncoded pins the conversion this backend exists to get right.
//
// A token returns ECDSA as a fixed-width r‖s pair and crypto/ecdsa verifies ASN.1 DER. Handing the raw
// pair over would produce a signature every host refuses as coming from no trusted signer, which reads
// as a broken trust anchor days later and on machines nobody can inspect. Both halves are asserted:
// what the backend returns is DER, and the token's own bytes are not.
func TestGuaranteeAnECDSASignatureIsDEREncoded(t *testing.T) {
	modulePath := tokenFixture(t)

	signer, err := open(context.Background(), reference(modulePath, testECLabel), pinPrompt(testUserPIN))
	if err != nil {
		t.Fatalf("opening the token: %v", err)
	}
	defer func() { _ = signer.Close() }()

	payload := []byte("what the operator approved")
	signature, err := signer.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	var parsed struct {
		// R and S are the signature's two halves.
		R, S *big.Int
	}
	rest, err := asn1.Unmarshal(signature, &parsed)
	if err != nil || len(rest) != 0 {
		t.Fatalf("the signature is not a DER SEQUENCE of two INTEGERs: %v (%d trailing bytes)",
			err, len(rest))
	}
	if parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 {
		t.Fatal("the signature carries a non-positive component")
	}

	// And the raw form the token produced would not have verified, which is the whole point.
	raw := make([]byte, 64)
	parsed.R.FillBytes(raw[:32])
	parsed.S.FillBytes(raw[32:])
	key := signing.PublicKey{Algorithm: signing.ECDSAP256, Key: signer.Public()}
	if key.Verify(payload, raw) {
		t.Fatal("a raw r‖s signature verified, so this test proves nothing")
	}
	if !key.Verify(payload, signature) {
		t.Fatal("the converted signature does not verify")
	}
}

// TestOpenRefusesTheWrongPIN proves the PIN protects something.
//
// One attempt only. SoftHSM locks the user PIN after three wrong ones, and a test that burned them
// would poison the shared fixture for every case after it — which would look like this backend
// failing rather than like the token doing exactly what a token should.
func TestOpenRefusesTheWrongPIN(t *testing.T) {
	modulePath := tokenFixture(t)

	signer, err := open(context.Background(), reference(modulePath, testECLabel), pinPrompt("0000"))
	if err == nil {
		_ = signer.Close()
		t.Fatal("a wrong PIN opened the token")
	}
	if !strings.Contains(err.Error(), "PIN") {
		t.Fatalf("the refusal does not name the PIN: %v", err)
	}
}

// TestOpenNamesAKeyItCannotCarry is issue #22's second bullet.
//
// A reference that names no key on the token must fail at Open, saying so, rather than at signing
// time — and certainly rather than producing something that does not verify.
func TestOpenNamesAKeyItCannotCarry(t *testing.T) {
	modulePath := tokenFixture(t)

	_, err := open(context.Background(), reference(modulePath, "no-such-key"), pinPrompt(testUserPIN))
	if err == nil {
		t.Fatal("a reference naming no key opened a signer")
	}
	if !strings.Contains(err.Error(), "no private key") && !strings.Contains(err.Error(), "no public key") {
		t.Fatalf("the refusal does not say what was missing: %v", err)
	}
}

// TestSignHonoursACancelledContext covers the affordance the whole interface carries a context for.
//
// A touch-required token blocks until somebody puts a finger on it, and an operator who changes their
// mind must get their terminal back. What that does not do is stop the token, which the doc comment on
// Sign says plainly rather than implying otherwise.
func TestSignHonoursACancelledContext(t *testing.T) {
	modulePath := tokenFixture(t)

	signer, err := open(context.Background(), reference(modulePath, testECLabel), pinPrompt(testUserPIN))
	if err != nil {
		t.Fatalf("opening the token: %v", err)
	}
	defer func() { _ = signer.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := signer.Sign(ctx, []byte("payload")); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled context produced %v", err)
	}
}

// TestCloseDropsTheSession proves a closed signer stops working rather than calling into a finalised
// module, which is a crash in somebody else's C rather than an error in Go.
func TestCloseDropsTheSession(t *testing.T) {
	modulePath := tokenFixture(t)

	signer, err := open(context.Background(), reference(modulePath, testEdLabel), pinPrompt(testUserPIN))
	if err != nil {
		t.Fatalf("opening the token: %v", err)
	}
	if err := signer.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
	if err := signer.Close(); err != nil {
		t.Fatalf("closing twice: %v", err)
	}
	if _, err := signer.Sign(context.Background(), []byte("payload")); err == nil {
		t.Fatal("a closed signer signed")
	}
}

// TestInspectRendersTheTrustedSignersEntry covers `farrier key show` against a token.
func TestInspectRendersTheTrustedSignersEntry(t *testing.T) {
	modulePath := tokenFixture(t)

	pub, err := inspect(context.Background(), reference(modulePath, testEdLabel), pinPrompt(testUserPIN))
	if err != nil {
		t.Fatalf("inspecting: %v", err)
	}
	if pub.KeyID != testEdLabel || pub.Backend != "pkcs11" || pub.Algorithm != signing.Ed25519 {
		t.Fatalf("the entry reads %+v", pub)
	}
	key, err := signing.ParsePublicKey(pub.Algorithm, pub.Encoded)
	if err != nil {
		t.Fatalf("the encoded key does not parse: %v", err)
	}
	if _, ok := key.(ed25519.PublicKey); !ok {
		t.Fatalf("the encoded key is a %T", key)
	}
}

// TestDERFromRSRefusesWhatItCannotConvert keeps the conversion strict.
//
// A token that returned an unexpected length is a fault worth naming, not a shape to guess at: every
// guess produces a signature that fails on a fleet rather than here.
func TestDERFromRSRefusesWhatItCannotConvert(t *testing.T) {
	for _, raw := range [][]byte{
		make([]byte, 63),
		make([]byte, 65),
		make([]byte, 64), // all zero: r and s are both zero, which is not a signature
		nil,
	} {
		if _, err := derFromRS(raw); err == nil {
			t.Errorf("a %d-byte signature was converted", len(raw))
		}
	}
}

// TestAReferenceWhoseKeyIDCannotBeWrittenDownIsRefused catches a label at the keyboard rather than
// after a fleet-wide edit.
//
// The key id here is the object label, because that is the name a person gave the key — and PKCS#11
// permits a space in it, which OpenSC's PIV objects use. A trusted-signers line is whitespace-
// separated, so such an id makes a five-field line, and signing.ParseSigners abandons the whole file
// on the first bad line rather than skipping it: pasting that line onto a host stops every other key
// already trusted there from authorising anything.
//
// Refused during parsing, which is before the module is dlopened and before the operator is asked for
// a PIN — so the failure costs a message rather than a touch on a token. The label itself is never
// trimmed or normalised: findOne matches CKA_LABEL byte-for-byte, so a normalised object= would stop
// finding the key it names, which is why the message points at id=<hex> instead.
func TestAReferenceWhoseKeyIDCannotBeWrittenDownIsRefused(t *testing.T) {
	const module = "?module-path=/usr/lib/softhsm/libsofthsm2.so"

	for _, ref := range []string{
		"token=ops;object=ops key 1" + module,
		"token=ops;object=ops%20key%201" + module,
		"token=ops;object=ops\tkey" + module,
	} {
		_, err := parseURI(ref)
		if err == nil {
			t.Errorf("%q was accepted; the line it produces would disarm a host's whole trust anchor", ref)
			continue
		}
		if !strings.Contains(err.Error(), "whitespace") {
			t.Errorf("%q: the refusal does not say why: %v", ref, err)
		}
		if !strings.Contains(err.Error(), "id=<hex>") {
			t.Errorf("%q: the refusal names no way out: %v", ref, err)
		}
	}

	// The two references that must keep working: an ordinary label, and the hex fallback a key found
	// by CKA_ID alone is recorded under.
	for _, ref := range []string{
		"token=ops;object=ops-yubikey-1" + module,
		"token=ops;id=%01%02" + module,
	} {
		if _, err := parseURI(ref); err != nil {
			t.Errorf("%q was refused: %v", ref, err)
		}
	}
}
