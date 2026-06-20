// Command go_runner fingerprints QUIC connections in pcap/pcapng files using the
// clienthellod library, emitting the conformance harness's canonical JSON record
// (one per QUIC connection) to stdout.
//
// It reads pcaps with pure-Go gopacket/pcapgo (no libpcap), extracts UDP
// payloads, groups client Initials by DCID (the per-connection initial random),
// and feeds each group to clienthellod's GatherClientInitials in arrival order --
// mirroring how pyquicfp groups and reassembles, so the two outputs line up by
// conn_key (DCID hex).
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	chd "github.com/refraction-networking/clienthellod"
)

// Canonical record schema -- must match pyquicfp.fingerprint.CanonicalRecord.to_dict().

type quicHeader struct {
	Version            uint32 `json:"version"`
	DCIDLen            uint32 `json:"dcid_len"`
	SCIDLen            uint32 `json:"scid_len"`
	PacketNumberLength int    `json:"packet_number_length"`
	SortedUniqueFrames []int  `json:"sorted_unique_frames"`
	TokenPresence      int    `json:"token_presence"`
}

type tlsFields struct {
	Version             uint16   `json:"version"`
	CipherSuites        []int    `json:"cipher_suites"`
	CompressionMethods  []int    `json:"compression_methods"`
	ExtensionsSorted    []int    `json:"extensions_sorted"`
	NamedGroups         []int    `json:"named_groups"`
	ECPointFormats      []int    `json:"ec_point_formats"`
	SignatureAlgorithms []int    `json:"signature_algorithms"`
	ALPN                []string `json:"alpn"`
	KeyShare            []int    `json:"key_share"`
	PSKKeyExchangeModes []int    `json:"psk_key_exchange_modes"`
	SupportedVersions   []int    `json:"supported_versions"`
	CertCompressionAlgs []int    `json:"cert_compression_algs"`
	RecordSizeLimit     *int     `json:"record_size_limit"`
}

type qtpFields struct {
	ParameterIDs                   []uint64 `json:"parameter_ids"`
	MaxIdleTimeout                 uint64   `json:"max_idle_timeout"`
	MaxUDPPayloadSize              uint64   `json:"max_udp_payload_size"`
	InitialMaxData                 uint64   `json:"initial_max_data"`
	InitialMaxStreamDataBidiLocal  uint64   `json:"initial_max_stream_data_bidi_local"`
	InitialMaxStreamDataBidiRemote uint64   `json:"initial_max_stream_data_bidi_remote"`
	InitialMaxStreamDataUni        uint64   `json:"initial_max_stream_data_uni"`
	InitialMaxStreamsBidi          uint64   `json:"initial_max_streams_bidi"`
	InitialMaxStreamsUni           uint64   `json:"initial_max_streams_uni"`
	AckDelayExponent               uint64   `json:"ack_delay_exponent"`
	MaxAckDelay                    uint64   `json:"max_ack_delay"`
	ActiveConnectionIDLimit        uint64   `json:"active_connection_id_limit"`
}

type record struct {
	ConnKey      string     `json:"conn_key"`
	QUICHeaderFP string     `json:"quic_header_fp"`
	TLSFP        string     `json:"tls_fp"`
	QTPFP        string     `json:"qtp_fp"`
	SuperFP      string     `json:"super_fp"`
	QUICHeader   quicHeader `json:"quic_header"`
	TLS          tlsFields  `json:"tls"`
	QTP          qtpFields  `json:"qtp"`
}

// ── GREASE normalisation (match pyquicfp.fingerprint) ─────────────────────────

func isGREASEU16(v uint16) bool {
	return byte(v>>8) == byte(v&0xFF) && (byte(v)&0x0F) == 0x0A
}

func ungreaseU16(v uint16) int {
	if isGREASEU16(v) {
		return 0x0A0A
	}
	return int(v)
}

var pskGREASE = map[byte]bool{0x0B: true, 0x2A: true, 0x49: true, 0x68: true,
	0x87: true, 0xA6: true, 0xC5: true, 0xE4: true}

func ungreasePSK(b byte) int {
	if pskGREASE[b] {
		return 0x0B
	}
	return int(b)
}

func ungreaseList(vs []uint16) []int {
	out := make([]int, 0, len(vs))
	for _, v := range vs {
		out = append(out, ungreaseU16(v))
	}
	return out
}

func bytesToInts(b []byte) []int {
	out := make([]int, 0, len(b))
	for _, v := range b {
		out = append(out, int(v))
	}
	return out
}

func u64hex(v uint64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return hex.EncodeToString(b[:])
}

// decodeBE decodes a clienthellod transport-parameter value (already passed
// through unsetVLIBits) as a big-endian integer -- equivalent to vliToU64.
func decodeBE(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

// ── pcap reading ──────────────────────────────────────────────────────────────

func packetSource(path string) (*gopacket.PacketSource, *os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	magic := make([]byte, 4)
	if _, err := f.ReadAt(magic, 0); err != nil {
		f.Close()
		return nil, nil, err
	}
	if magic[0] == 0x0A && magic[1] == 0x0D && magic[2] == 0x0D && magic[3] == 0x0A {
		ng, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		return gopacket.NewPacketSource(ng, ng.LinkType()), f, nil
	}
	r, err := pcapgo.NewReader(f)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return gopacket.NewPacketSource(r, r.LinkType()), f, nil
}

// dcidOf extracts the DCID from a QUIC long-header packet, or nil.
func dcidOf(p []byte) []byte {
	if len(p) < 6 || p[0]&0xC0 != 0xC0 {
		return nil
	}
	dcidLen := int(p[5])
	if 6+dcidLen > len(p) {
		return nil
	}
	out := make([]byte, dcidLen)
	copy(out, p[6:6+dcidLen])
	return out
}

func dedupSortedUint8(ts []uint64) []int {
	u8 := make([]int, 0, len(ts))
	for _, t := range ts {
		u8 = append(u8, int(t&0xFF))
	}
	sort.Ints(u8)
	out := u8[:0]
	for i, v := range u8 {
		if i == 0 || v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

func buildRecord(connKey string, gci *chd.GatheredClientInitials) (*record, error) {
	qfp, err := chd.GenerateQUICFingerprint(gci)
	if err != nil {
		return nil, err
	}
	ch := gci.ClientHello
	qtp := gci.TransportParameters
	hdr := gci.Packets[0].Header

	var rsl *int
	if len(ch.RecordSizeLimit) >= 2 {
		v := int(binary.BigEndian.Uint16(ch.RecordSizeLimit[:2]))
		rsl = &v
	}

	certAlgs := make([]int, 0, len(ch.CertCompressAlgo))
	for _, a := range ch.CertCompressAlgo {
		certAlgs = append(certAlgs, int(a))
	}

	rec := &record{
		ConnKey:      connKey,
		QUICHeaderFP: u64hex(gci.NumID),
		TLSFP:        u64hex(uint64(ch.NormNumID)),
		QTPFP:        u64hex(qtp.NumID),
		SuperFP:      u64hex(qfp.NumID),
		QUICHeader: quicHeader{
			Version:            binary.BigEndian.Uint32(hdr.Version),
			DCIDLen:            hdr.DCIDLength,
			SCIDLen:            hdr.SCIDLength,
			PacketNumberLength: len(hdr.PacketNumber),
			SortedUniqueFrames: dedupSortedUint8(gci.Packets[0].FrameTypes),
			TokenPresence:      boolToInt(hdr.HasToken),
		},
		TLS: tlsFields{
			Version:             ch.TLSHandshakeVersion,
			CipherSuites:        ungreaseList(ch.CipherSuites),
			CompressionMethods:  bytesToInts(ch.CompressionMethods),
			ExtensionsSorted:    ungreaseList(ch.ExtensionsNormalized),
			NamedGroups:         ungreaseList(ch.NamedGroupList),
			ECPointFormats:      bytesToInts(ch.ECPointFormatList),
			SignatureAlgorithms: ungreaseList(ch.SignatureSchemeList),
			ALPN:                normALPN(ch.ALPN),
			KeyShare:            ungreaseList(ch.KeyShare),
			PSKKeyExchangeModes: ungreasePSKList(ch.PSKKeyExchangeModes),
			SupportedVersions:   ungreaseList(ch.SupportedVersions),
			CertCompressionAlgs: certAlgs,
			RecordSizeLimit:     rsl,
		},
		QTP: qtpFields{
			ParameterIDs:                   qtp.QTPIDs,
			MaxIdleTimeout:                 decodeBE(qtp.MaxIdleTimeout),
			MaxUDPPayloadSize:              decodeBE(qtp.MaxUDPPayloadSize),
			InitialMaxData:                 decodeBE(qtp.InitialMaxData),
			InitialMaxStreamDataBidiLocal:  decodeBE(qtp.InitialMaxStreamDataBidiLocal),
			InitialMaxStreamDataBidiRemote: decodeBE(qtp.InitialMaxStreamDataBidiRemote),
			InitialMaxStreamDataUni:        decodeBE(qtp.InitialMaxStreamDataUni),
			InitialMaxStreamsBidi:          decodeBE(qtp.InitialMaxStreamsBidi),
			InitialMaxStreamsUni:           decodeBE(qtp.InitialMaxStreamsUni),
			AckDelayExponent:               decodeBE(qtp.AckDelayExponent),
			MaxAckDelay:                    decodeBE(qtp.MaxAckDelay),
			ActiveConnectionIDLimit:        decodeBE(qtp.ActiveConnectionIDLimit),
		},
	}
	if rec.QTP.ParameterIDs == nil {
		rec.QTP.ParameterIDs = []uint64{}
	}
	return rec, nil
}

// normALPN un-GREASEs ALPN protocol strings so the canonical field matches
// pyquicfp and retina (GREASE 2-byte values -> "\x0a\x0a"). This also keeps the
// emitted JSON valid: raw GREASE bytes are invalid UTF-8 and would otherwise be
// mangled to U+FFFD by encoding/json.
func normALPN(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if len(s) == 2 && s[0] == s[1] && (s[0]&0x0F) == 0x0A {
			out = append(out, "\x0a\x0a")
		} else {
			out = append(out, s)
		}
	}
	return out
}

func ungreasePSKList(b []byte) []int {
	out := make([]int, 0, len(b))
	for _, x := range b {
		out = append(out, ungreasePSK(x))
	}
	return out
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func fingerprintPcap(path string, enc *json.Encoder) {
	src, f, err := packetSource(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s: %v\n", path, err)
		return
	}
	defer f.Close()

	type group struct {
		gci  *chd.GatheredClientInitials
		done bool
	}
	groups := map[string]*group{}
	var order []string
	deadline := time.Now().Add(time.Hour)
	debug := os.Getenv("DEBUG") != ""
	var nUDP, nUnmarshalOK, nUnmarshalErr int

	for pkt := range src.Packets() {
		udpLayer := pkt.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}
		payload := udpLayer.(*layers.UDP).Payload
		if len(payload) == 0 {
			continue
		}
		nUDP++
		cip, err := chd.UnmarshalQUICClientInitialPacket(payload)
		if err != nil {
			nUnmarshalErr++
			if debug && nUnmarshalErr <= 3 {
				fmt.Fprintf(os.Stderr, "DEBUG unmarshal err: %v\n", err)
			}
			continue // not a (decryptable) client Initial
		}
		nUnmarshalOK++
		dcid := dcidOf(payload)
		if dcid == nil {
			continue
		}
		key := hex.EncodeToString(dcid)
		g, ok := groups[key]
		if !ok {
			g = &group{gci: chd.GatherClientInitialsWithDeadline(deadline)}
			groups[key] = g
			order = append(order, key)
		}
		if g.done {
			continue
		}
		// AddPacket applies clienthellod's accept/dedup/reassembly logic.
		addErr := g.gci.AddPacket(cip)
		if debug && addErr != nil {
			fmt.Fprintf(os.Stderr, "DEBUG AddPacket key=%s pn=%v frames=%v err=%v\n",
				key[:12], cip.Header.PacketNumber, cip.FrameTypes, addErr)
		}
		if g.gci.Completed() {
			g.done = true
		}
	}

	if debug {
		nComplete := 0
		for _, g := range groups {
			if g.gci.Completed() {
				nComplete++
			}
		}
		fmt.Fprintf(os.Stderr,
			"DEBUG %s: udp=%d unmarshal_ok=%d unmarshal_err=%d groups=%d complete=%d\n",
			path, nUDP, nUnmarshalOK, nUnmarshalErr, len(groups), nComplete)
	}

	for _, key := range order {
		g := groups[key]
		if !g.gci.Completed() {
			continue
		}
		rec, err := buildRecord(key, g.gci)
		if err != nil {
			continue
		}
		if err := enc.Encode(rec); err != nil {
			fmt.Fprintf(os.Stderr, "error encoding %s: %v\n", path, err)
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go_runner <pcap...>")
		os.Exit(2)
	}
	enc := json.NewEncoder(os.Stdout)
	for _, path := range os.Args[1:] {
		fingerprintPcap(path, enc)
	}
}
