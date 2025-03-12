package stateless

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"

	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/header"
	"github.com/ghettovoice/gosip/sip/transport"
	"github.com/ghettovoice/gosip/sip/uri"
)

var DefaultSupportedSchemes = []string{"sip", "sips"}

type Proxy struct {
	DetectLoops       bool
	SupportedFeatures []string

	// If nil, DefaultSupportedSchemes is used.
	SupportedSchemes []string
	URI              uri.URI
	Transport        sip.Transport
	transports       []sip.Transport

	hash crypto.Hash
}

func (p *Proxy) BindTo(ts ...sip.Transport) {
	p.hash = crypto.SHA256
	for _, t := range ts {
		p.transports = append(p.transports, t)
		t.OnInboundRequest(p.handleInboundRequest)
		t.OnInboundResponse(p.handleInboundResponse)
	}
}

func (p *Proxy) handleInboundResponse(ctx context.Context, response *sip.Response) error {
	conn, ok := transport.Connection(ctx)
	if !ok {
		return errors.New("no packet conn")
	}

	if vias := slices.Collect(headersVia(response.Headers)); len(vias) > 1 {
		if front, rest, ok := PopFront(vias); ok {
			if todo(front.Addr.String() != "") { // Check if this is this proxy.
				response.Headers.Set(header.Via(rest))

				// from, err := net.ResolveUDPAddr("udp", front.Addr.String())
				// if err != nil {
				//	return nil
				// }

				to, err := net.ResolveUDPAddr("udp", rest[0].Addr.String())
				if err != nil {
					return nil
				}

				var buf bytes.Buffer
				err = response.RenderTo(&buf)
				if err != nil {
					return fmt.Errorf("failed to render response: %v", err)
				}
				slog.Info(fmt.Sprintf("Forwarding response %d, %s", response.Status, response.Reason))
				_, err = conn.WriteTo(buf.Bytes(), to)
				if err != nil {
					return fmt.Errorf("failed to write response: %v", err)
				}

			}
		}
	} else {
		slog.Info(fmt.Sprintf("Discarded response %d, %s", response.Status, response.Reason))
	}

	return nil
}

func todo(b bool) bool {
	return b
}

func removeMaddr(_ sip.URI) sip.URI {
	panic("not implemented yet")
}

func (p *Proxy) hasMAddr(u sip.URI) (string, bool) {
	return "", todo(false)
}

func (p *Proxy) isResponsibleFor(req *sip.Request) bool {
	return todo(false)
}

func (p *Proxy) samePortAndTransport(req *sip.Request, maddr string) bool {
	return todo(false)
}

func (p *Proxy) findTargets(ctx context.Context, req *sip.Request) ([]sip.URI, error) {
	var addr uri.Addr
	if suri, ok := req.URI.(*uri.SIP); ok {
		switch suri.User.Username() {
		case "one":
			addr = uri.HostPort("127.0.0.1", 1234)
		case "two":
			addr = uri.HostPort("127.0.0.1", 2234)
		default:
			return nil, nil
		}
	}
	return []sip.URI{
		&uri.SIP{
			Addr: addr,
		},
	}, nil
}

func (s *Proxy) handleInboundRequest(ctx context.Context, req *sip.Request, w sip.ResponseWriter) (err error) {
	sm := &fsm{Proxy: s}
	return sm.handleInboundRequest(ctx, req, w)
}

func (p *Proxy) marker(req *sip.Request) (string, error) {
	return hash(p.hash, req.Headers.CallID())
}

func (p *Proxy) isURIMarked(req *sip.Request, uri sip.URI) (bool, error) {
	marker, err := p.marker(req)
	if err != nil {
		return false, err
	}
	return uriParam(uri).Has(marker), nil
}
