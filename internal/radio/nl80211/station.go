package nl80211

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

// StationConn is a kernel-driven association whose 802.1X control port runs over nl80211.
//
// This is the transport the certificate harvest needs on hardware where the control port does not
// work over the data path: instead of a packet socket on the netdev (which on many drivers sends
// EAPOL that never reaches the air), the EAPOL exchange rides NL80211_CMD_CONTROL_PORT_FRAME on
// the netlink socket that owns the association. It is exactly what modern wpa_supplicant does.
//
// Two sockets: rx owns the association (CMD_CONNECT was issued on it with SOCKET_OWNER, so the
// kernel delivers the control-port frames back to it, and closing it drops the association) and is
// used only to receive; tx issues the control-port-frame sends. Keeping them apart means a send's
// command/ack handshake cannot swallow a queued inbound EAPOL frame.
type StationConn struct {
	rx      *genetlink.Conn
	tx      *genetlink.Conn
	famID   uint16
	version uint8
	ifindex uint32
	bssid   [6]byte

	sent     atomic.Uint64
	received atomic.Uint64
}

// Associate puts a real association on ifindex and returns a transport for the EAPOL exchange over
// it. params must describe the network (SSID/BSSID/freq/crypto); control-port-over-nl80211 and
// socket-owner are forced on regardless of what the caller set, because that is the whole point.
//
// It blocks until the association completes or timeout elapses, returning the access point's
// 802.11 status code as an error if it was refused.
func Associate(ifindex uint32, params ConnectParams, timeout time.Duration) (*StationConn, error) {
	if len(params.BSSID) != 6 {
		return nil, fmt.Errorf("nl80211: associate needs a 6-byte BSSID, got %d", len(params.BSSID))
	}

	rx, err := genetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("nl80211: open station socket: %w", err)
	}
	fam, err := rx.GetFamily(FamilyName)
	if err != nil {
		rx.Close()
		return nil, fmt.Errorf("nl80211: resolve family: %w", err)
	}
	tx, err := genetlink.Dial(nil)
	if err != nil {
		rx.Close()
		return nil, fmt.Errorf("nl80211: open control-port send socket: %w", err)
	}

	s := &StationConn{rx: rx, tx: tx, famID: fam.ID, version: fam.Version, ifindex: ifindex}
	copy(s.bssid[:], params.BSSID)

	// Clear any association the interface is already in, *before* joining the mlme multicast group.
	// A supplicant that reclaimed the card (the "reverted to managed" symptom) may have it connected
	// or connecting; issuing CMD_CONNECT over the top of that is refused. This is an ordinary
	// request/reply (Execute) and it must run before the group join: once the socket is receiving
	// multicast mlme events, Execute's reply-sequence validation trips over one of them and fails
	// with "mismatched sequence in netlink reply". Best-effort - "not connected" is the normal,
	// harmless result.
	if dae := disconnectAttrs(ifindex); dae != nil {
		if dd, derr := dae.Encode(); derr == nil {
			_, _ = rx.Execute(
				genetlink.Message{Header: genetlink.Header{Command: CmdDisconnect, Version: fam.Version}, Data: dd},
				fam.ID, netlink.Request|netlink.Acknowledge,
			)
		}
	}

	// Join mlme so the connect/auth/assoc results are caught even on kernels that multicast them
	// rather than unicasting to the owning socket, and - for the manual MLME path - scan, so the
	// scan-completion event that must precede CMD_AUTHENTICATE is caught too.
	for _, g := range fam.Groups {
		if g.Name == "mlme" || (params.ManualMLME && g.Name == "scan") {
			_ = rx.JoinGroup(g.ID)
		}
	}

	// WPS needs an open association carrying a WSC element, which the connection manager will not
	// do to a secured access point. Drive it by hand with CMD_AUTHENTICATE + CMD_ASSOCIATE instead.
	if params.ManualMLME {
		if err := s.authAssoc(params, timeout); err != nil {
			s.Close()
			return nil, err
		}
		return s, nil
	}

	// Force the over-nl80211 control port and socket ownership on the rx socket.
	params.ControlPortOverNL80211 = true
	ae, err := connectAttrs(ifindex, params)
	if err != nil {
		s.Close()
		return nil, err
	}
	data, err := ae.Encode()
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("nl80211: encode connect: %w", err)
	}

	// Issue CMD_CONNECT with Send, not Execute. The socket is now in the mlme multicast group so it
	// receives association events, and Execute validates that the reply's sequence matches the
	// request - a multicast mlme message (sequence 0) landing between the request and its ack makes
	// that validation fail with "mismatched sequence in netlink reply", which is intermittent and
	// depends purely on timing. Send performs no such validation; waitConnect reads the ack, any
	// netlink error, and the CMD_CONNECT event off the socket directly.
	if _, err := rx.Send(
		genetlink.Message{Header: genetlink.Header{Command: CmdConnect, Version: fam.Version}, Data: data},
		fam.ID, netlink.Request|netlink.Acknowledge,
	); err != nil {
		s.Close()
		return nil, fmt.Errorf("nl80211: issue connect: %w", err)
	}

	status, err := s.waitConnect(timeout)
	if err != nil {
		s.Close()
		return nil, err
	}
	if status != 0 {
		s.Close()
		return nil, fmt.Errorf("nl80211: association refused - 802.11 status %d", status)
	}
	return s, nil
}

// authAssoc drives an open authentication and association by hand - CMD_AUTHENTICATE then
// CMD_ASSOCIATE - rather than through the connection manager. This is the association a WPS
// enrollee makes: open (no RSN) carrying a WSC element (params.ExtraIE), which the connection
// manager refuses to a secured AP. The 802.1X control port rides the owning socket the same as the
// CMD_CONNECT path, so the WSC/EAP exchange that follows is identical.
//
// Both commands are issued with Send (not Execute): the socket is in the mlme multicast group and
// Execute's reply-sequence validation would trip over an event. The auth/associate results come
// back as CMD_AUTHENTICATE / CMD_ASSOCIATE events carrying the response management frame, whose
// 802.11 status code is parsed out.
func (s *StationConn) authAssoc(params ConnectParams, timeout time.Duration) error {
	// No pre-deauthentication here: the interface was just switched to managed mode and is not
	// authenticated to anything, so CMD_DEAUTHENTICATE would return -ENOTCONN, and that error
	// message, arriving on the shared socket, is then read as the authentication's own failure
	// ("transport endpoint is not connected").

	// CMD_AUTHENTICATE only works against a BSS already in the interface's scan cache, and that
	// cache is empty right after the switch to managed mode (recon's beacons were heard on a
	// monitor interface). A fast directed scan of the target channel populates it - this is the
	// step wpa_supplicant does before every authenticate, and without it the kernel returns ENOENT
	// ("no such file or directory").
	if err := s.scanForBSS(params, timeout); err != nil {
		return err
	}

	// CMD_AUTHENTICATE - open system.
	authAE := netlink.NewAttributeEncoder()
	authAE.Uint32(AttrIfindex, s.ifindex)
	authAE.Bytes(AttrMAC, params.BSSID)
	authAE.Uint32(AttrWiphyFreq, uint32(params.FreqMHz))
	authAE.Bytes(AttrSSID, params.SSID)
	authAE.Uint32(AttrAuthType, uint32(AuthTypeOpenSystem))
	authData, err := authAE.Encode()
	if err != nil {
		return fmt.Errorf("nl80211: encode authenticate: %w", err)
	}
	if _, err := s.rx.Send(genetlink.Message{
		Header: genetlink.Header{Command: CmdAuthenticate, Version: s.version}, Data: authData,
	}, s.famID, netlink.Request|netlink.Acknowledge); err != nil {
		return fmt.Errorf("nl80211: issue authenticate: %w", err)
	}
	if status, err := s.waitMLME(CmdAuthenticate, authRespOffset, timeout); err != nil {
		return fmt.Errorf("nl80211: authentication did not complete: %w", err)
	} else if status != 0 {
		return fmt.Errorf("nl80211: authentication refused - 802.11 status %d", status)
	}

	// CMD_ASSOCIATE - open, carrying the WSC element, with the control port owned by this socket.
	assocAE := netlink.NewAttributeEncoder()
	assocAE.Uint32(AttrIfindex, s.ifindex)
	assocAE.Bytes(AttrMAC, params.BSSID)
	assocAE.Uint32(AttrWiphyFreq, uint32(params.FreqMHz))
	assocAE.Bytes(AttrSSID, params.SSID)
	if len(params.ExtraIE) > 0 {
		assocAE.Bytes(AttrIE, params.ExtraIE)
	}
	assocAE.Flag(AttrControlPort, true)
	assocAE.Uint16(AttrControlPortEthertype, EtherTypeEAPOL)
	assocAE.Flag(AttrControlPortOverNL80211, true)
	assocAE.Flag(AttrSocketOwner, true)
	assocData, err := assocAE.Encode()
	if err != nil {
		return fmt.Errorf("nl80211: encode associate: %w", err)
	}
	if _, err := s.rx.Send(genetlink.Message{
		Header: genetlink.Header{Command: CmdAssociate, Version: s.version}, Data: assocData,
	}, s.famID, netlink.Request|netlink.Acknowledge); err != nil {
		return fmt.Errorf("nl80211: issue associate: %w", err)
	}
	if status, err := s.waitMLME(CmdAssociate, assocRespOffset, timeout); err != nil {
		return fmt.Errorf("nl80211: association did not complete: %w", err)
	} else if status != 0 {
		return fmt.Errorf("nl80211: association refused - 802.11 status %d", status)
	}
	return nil
}

// scanForBSS triggers a directed scan of the target channel and waits for it to complete, so the
// access point is in the interface's scan cache before CMD_AUTHENTICATE. It is directed (one SSID,
// one frequency) so it finishes in a fraction of a second rather than sweeping every channel.
func (s *StationConn) scanForBSS(params ConnectParams, timeout time.Duration) error {
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(AttrIfindex, s.ifindex)
	// Actively probe for exactly this SSID...
	ae.Nested(AttrScanSSIDs, func(n *netlink.AttributeEncoder) error {
		n.Bytes(1, params.SSID)
		return nil
	})
	// ...on exactly this channel. Both lists are nested attributes indexed from 1.
	if params.FreqMHz > 0 {
		ae.Nested(AttrScanFrequencies, func(n *netlink.AttributeEncoder) error {
			n.Uint32(1, uint32(params.FreqMHz))
			return nil
		})
	}
	data, err := ae.Encode()
	if err != nil {
		return fmt.Errorf("nl80211: encode scan request: %w", err)
	}
	if _, err := s.rx.Send(genetlink.Message{
		Header: genetlink.Header{Command: CmdTriggerScan, Version: s.version}, Data: data,
	}, s.famID, netlink.Request|netlink.Acknowledge); err != nil {
		return fmt.Errorf("nl80211: trigger scan: %w", err)
	}

	// Wait for the scan to finish. A completed scan (new results) is what we want; an aborted scan
	// still leaves whatever was cached, so proceed on that too rather than failing.
	deadline := time.Now().Add(timeout)
	if err := s.rx.SetReadDeadline(deadline); err != nil {
		return err
	}
	for {
		msgs, _, err := s.rx.Receive()
		if err != nil {
			// A read timeout means the completion event was missed; the cache is very likely
			// populated regardless, so let the authentication be the real test rather than failing
			// the whole attempt here.
			if isTimeout(err) {
				return nil
			}
			return fmt.Errorf("nl80211: waiting for scan results: %w", err)
		}
		for _, m := range msgs {
			if m.Header.Command == CmdNewScanResults || m.Header.Command == CmdScanAborted {
				return nil
			}
		}
	}
}

// Status-code offset within the body of an 802.11 management response frame, measured from the end
// of the 24-byte header. An authentication response is algorithm(2) + seq(2) + status(2); an
// association response is capability(2) + status(2) + aid(2).
const (
	authRespOffset  = 4
	assocRespOffset = 2
)

// waitMLME reads mlme events until the given CMD_AUTHENTICATE/CMD_ASSOCIATE result for our
// interface arrives, returning the 802.11 status code parsed from the response frame. statusOffset
// is where the status sits within the frame body (authRespOffset / assocRespOffset).
func (s *StationConn) waitMLME(cmd uint8, statusOffset int, timeout time.Duration) (uint16, error) {
	if err := s.rx.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}
	for {
		msgs, _, err := s.rx.Receive()
		if err != nil {
			return 0, err
		}
		for _, m := range msgs {
			if m.Header.Command != cmd {
				continue
			}
			ifi, frame, haveIf := parseMLMEEvent(m.Data)
			if !haveIf || ifi != s.ifindex {
				continue
			}
			// The event carries the response management frame; the status is in it. If it could
			// not be read, the event arriving is itself taken as success (the driver would report a
			// failure differently), which keeps a driver that omits the frame from stalling us.
			return mgmtStatus(frame, statusOffset), nil
		}
	}
}

// parseMLMEEvent pulls the interface index and the response management frame out of a
// CMD_AUTHENTICATE / CMD_ASSOCIATE event.
func parseMLMEEvent(data []byte) (ifindex uint32, frame []byte, haveIf bool) {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return 0, nil, false
	}
	for ad.Next() {
		switch ad.Type() {
		case AttrIfindex:
			ifindex = ad.Uint32()
			haveIf = true
		case AttrFrame:
			frame = append([]byte(nil), ad.Bytes()...)
		}
	}
	return ifindex, frame, haveIf
}

// mgmtStatus reads the 2-byte little-endian 802.11 status code from a management response frame,
// at header(24)+statusOffset. Returns 0 (success) when the frame is absent or too short - see
// waitMLME.
func mgmtStatus(frame []byte, statusOffset int) uint16 {
	const hdr = 24
	if len(frame) < hdr+statusOffset+2 {
		return 0
	}
	return binary.LittleEndian.Uint16(frame[hdr+statusOffset : hdr+statusOffset+2])
}

// waitConnect reads mlme events until the CMD_CONNECT result for our interface arrives.
func (s *StationConn) waitConnect(timeout time.Duration) (uint16, error) {
	if err := s.rx.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}
	for {
		msgs, _, err := s.rx.Receive()
		if err != nil {
			return 0, fmt.Errorf("nl80211: waiting for the association to complete: %w", err)
		}
		for _, m := range msgs {
			if m.Header.Command != CmdConnect {
				continue
			}
			ifi, code, haveIf, haveCode := parseConnectEvent(m.Data)
			if !haveIf || ifi != s.ifindex {
				continue
			}
			if haveCode {
				return code, nil
			}
			return 0, nil
		}
	}
}

// Send transmits one EAPOL payload to the access point over the control port. It satisfies the
// harvest Transport interface.
func (s *StationConn) Send(ctx context.Context, eapol []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := controlPortFrameAttrs(s.ifindex, s.bssid[:], eapol).Encode()
	if err != nil {
		return fmt.Errorf("nl80211: encode control-port frame: %w", err)
	}
	if _, err := s.tx.Execute(
		genetlink.Message{Header: genetlink.Header{Command: CmdControlPortFrame, Version: s.version}, Data: data},
		s.famID, netlink.Request|netlink.Acknowledge,
	); err != nil {
		return fmt.Errorf("nl80211: send control-port frame: %w", err)
	}
	s.sent.Add(1)
	return nil
}

// Sent and Received report how many EAPOL frames crossed the control port, for diagnosis.
func (s *StationConn) Sent() uint64     { return s.sent.Load() }
func (s *StationConn) Received() uint64 { return s.received.Load() }

// Receive returns the next EAPOL payload the access point sent over the control port, or the
// context error. It satisfies the harvest Transport interface.
func (s *StationConn) Receive(ctx context.Context) ([]byte, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// A short read deadline so a silent exchange returns to re-check the context rather than
		// blocking forever.
		if err := s.rx.SetReadDeadline(time.Now().Add(400 * time.Millisecond)); err != nil {
			return nil, err
		}
		msgs, _, err := s.rx.Receive()
		if err != nil {
			if isTimeout(err) {
				continue
			}
			return nil, fmt.Errorf("nl80211: receive control-port frame: %w", err)
		}
		for _, m := range msgs {
			if m.Header.Command != CmdControlPortFrame {
				continue
			}
			ifi, frame := parseControlPortFrame(m.Data)
			if ifi != s.ifindex || len(frame) == 0 {
				continue
			}
			s.received.Add(1)
			return frame, nil
		}
	}
}

// Close drops the association (closing the owning socket does this via SOCKET_OWNER) and releases
// both sockets.
func (s *StationConn) Close() error {
	var errs []error
	if s.tx != nil {
		if err := s.tx.Close(); err != nil {
			errs = append(errs, err)
		}
		s.tx = nil
	}
	if s.rx != nil {
		// A best-effort explicit disconnect before dropping the socket, so the access point sees a
		// clean deauth rather than a silent timeout. Send, not Execute: the socket is in the mlme
		// multicast group, where Execute's reply-sequence validation would trip over a multicast
		// event ("mismatched sequence"). Closing the socket drops the association anyway via
		// SOCKET_OWNER, so this only needs to go out, not be acknowledged.
		if ae := disconnectAttrs(s.ifindex); ae != nil {
			if data, err := ae.Encode(); err == nil {
				_, _ = s.rx.Send(
					genetlink.Message{Header: genetlink.Header{Command: CmdDisconnect, Version: s.version}, Data: data},
					s.famID, netlink.Request,
				)
			}
		}
		if err := s.rx.Close(); err != nil {
			errs = append(errs, err)
		}
		s.rx = nil
	}
	return errors.Join(errs...)
}

// controlPortFrameAttrs builds the attribute set for a CMD_CONTROL_PORT_FRAME send: the frame goes
// to the access point (AttrMAC), carries the EAPOL ethertype, is sent unencrypted (EAPOL flows
// before any key is installed), and AttrFrame holds the 802.1X payload.
func controlPortFrameAttrs(ifindex uint32, dst, eapol []byte) *netlink.AttributeEncoder {
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(AttrIfindex, ifindex)
	ae.Bytes(AttrMAC, dst)
	ae.Uint16(AttrControlPortEthertype, EtherTypeEAPOL)
	ae.Flag(AttrControlPortNoEncrypt, true)
	ae.Bytes(AttrFrame, eapol)
	return ae
}

// disconnectAttrs builds the CMD_DISCONNECT attribute set.
func disconnectAttrs(ifindex uint32) *netlink.AttributeEncoder {
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(AttrIfindex, ifindex)
	return ae
}

// parseControlPortFrame pulls the interface index and EAPOL payload out of a CONTROL_PORT_FRAME
// notification.
func parseControlPortFrame(data []byte) (ifindex uint32, frame []byte) {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return 0, nil
	}
	for ad.Next() {
		switch ad.Type() {
		case AttrIfindex:
			ifindex = ad.Uint32()
		case AttrFrame:
			frame = append([]byte(nil), ad.Bytes()...)
		}
	}
	return ifindex, frame
}

// isTimeout reports whether err is a read-deadline timeout.
func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}
