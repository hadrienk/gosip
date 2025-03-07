package stateless

import (
	"bufio"
	"context"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net"
	"net/netip"
	"slices"

	"github.com/ghettovoice/gosip/internal/iterutils"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/header"
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
}

func (p *Proxy) BindTo(ts ...sip.Transport) {
	for _, t := range ts {
		t.OnInboundRequest(p.handleInboundRequest)
		t.OnInboundResponse(p.handleInboundResponse)
	}
}

// TODO: Why seq2 in message?
func headersVia(hdrs sip.Headers) iter.Seq[header.ViaHop] {
	return func(yield func(header.ViaHop) bool) {
		for _, hdr := range hdrs.Get("Via") {
			if via, ok := hdr.(header.Via); ok {
				for j := range via {
					if !yield(via[j]) {
						return
					}
				}
			}
		}
	}
}

func (p *Proxy) handleInboundResponse(ctx context.Context, response *sip.Response) error {
	if vias := slices.Collect(headersVia(response.Headers)); len(vias) > 1 {
		if front, rest, ok := PopFront(vias); ok {
			if todo(front.Addr.String() != "") { // Check if this is this proxy.
				response.Headers.Set(header.Via(rest))
				// TODO: Need a way to send the resp with the transport. Transaction layer leaks for now.
				slog.Info("Dialing", "addr", rest[0].Addr.String())
				dial, err := net.Dial("udp", rest[0].Addr.String())
				if err != nil {
					return err
				}
				defer dial.Close()
				buf := bufio.NewWriter(dial)
				err = response.RenderTo(buf)
				if err != nil {
					slog.Error("Dialing", "error", err)
					return err
				}
				return buf.Flush()
			}
		}
	}
	return nil
}

func todo(b bool) bool {
	return b
}

func removeMaddr(_ sip.URI) sip.URI {
	panic("not implemented yet")
}

func (p *Proxy) isURIMarked(sip.URI) bool {
	return todo(false)
}

func (p *Proxy) hasMAddr(u sip.URI) (string, bool) {
	return "", todo(false)
}

func (p *Proxy) isResponsibleFor(string) bool {
	return todo(false)
}

func (p *Proxy) samePortAndTransport(req *sip.Request, maddr string) bool {
	return todo(false)
}

func (p *Proxy) findTargets(ctx context.Context, req *sip.Request) ([]sip.URI, error) {
	return []sip.URI{
		&uri.SIP{
			Addr: uri.HostPort("127.0.0.1", 1234),
		},
	}, nil
}

type state func(ctx context.Context, req *sip.Request, w sip.ResponseWriter) (state, error)

func (s *Proxy) handleInboundRequest(ctx context.Context, req *sip.Request, w sip.ResponseWriter) (err error) {
	var st state = s.start
	for st != nil {
		st, err = st(ctx, req, w)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *Proxy) start(_ context.Context, _ *sip.Request, _ sip.ResponseWriter) (state, error) {
	return p.validateSyntax, nil
}

func (p *Proxy) validateSyntax(ctx context.Context, req *sip.Request, w sip.ResponseWriter) (state, error) {
	// TODO: investigate if the lower layer takes care of this.
	// https://datatracker.ietf.org/doc/html/rfc3261#section-16.3
	if !req.IsValid() {
		if err := w.Write(ctx, sip.ResponseStatusBadRequest); err != nil {
			return nil, err
		}
	}
	return p.validateScheme, nil
}

func uriScheme(u sip.URI) string {
	switch v := u.(type) {
	case *uri.SIP:
		if v.Secured {
			return "sips"
		} else {
			return "sip"
		}
	case *uri.Tel:
		return "tel"
	case *uri.Any:
		return v.Scheme
	default:
		return ""
	}
}

func (p *Proxy) validateScheme(ctx context.Context, req *sip.Request, w sip.ResponseWriter) (state, error) {
	var supported []string
	if p.SupportedSchemes == nil {
		supported = DefaultSupportedSchemes
	} else {
		supported = p.SupportedSchemes
	}
	if !slices.Contains(supported, uriScheme(req.URI)) {
		if err := w.Write(ctx, sip.ResponseStatusUnsupportedURIScheme); err != nil {
			return nil, err
		}
		return p.done, nil
	}
	return p.validateMaxForwards, nil
}

func (p *Proxy) validateMaxForwards(ctx context.Context, req *sip.Request, w sip.ResponseWriter) (state, error) {
	if req.Headers.Has("Max-Forwards") && req.Headers.MaxForwards() == 1 {
		// TODO: Handle options?
		if err := w.Write(ctx, sip.ResponseStatusTooManyHops); err != nil {
			return nil, err
		}
		return p.done, nil
	}
	return p.validateLoop, nil
}

func (p *Proxy) validateLoop(ctx context.Context, _ *sip.Request, w sip.ResponseWriter) (state, error) {
	if p.DetectLoops {
		// TODO: Implement loop detection
		if todo(false) {
			if err := w.Write(ctx, sip.ResponseStatusLoopDetected); err != nil {
				return nil, err
			}
			return p.done, nil
		}
	}
	return p.validateProxyRequire, nil
}

func (p *Proxy) validateProxyRequire(ctx context.Context, req *sip.Request, w sip.ResponseWriter) (state, error) {
	if req.Headers.Has("Proxy-Require") {
		var unsupported header.Unsupported
		for _, feature := range req.Headers.ProxyRequire() {
			if !slices.Contains(p.SupportedFeatures, feature) {
				unsupported = append(unsupported, feature)
			}
		}
		if len(unsupported) > 0 {
			w.Headers().Set(unsupported)
			if err := w.Write(ctx, sip.ResponseStatusBadExtension); err != nil {
				return nil, err
			}
			return p.done, nil
		}
	}
	return p.validateProxyAuth, nil
}

func (p *Proxy) validateProxyAuth(_ context.Context, _ *sip.Request, _ sip.ResponseWriter) (state, error) {
	if todo(false) {
		return nil, errors.New("implement me")
	}
	return p.routePreprocess, nil
}

func (p *Proxy) routePreprocess(ctx context.Context, req *sip.Request, _ sip.ResponseWriter) (state, error) {
	if p.isURIMarked(req.URI) {
		route := req.Headers.Route()
		n := len(route)
		var last header.EntityAddr
		if n < 1 {
			return nil, sip.ErrInvalidMessage
		}
		route, last = route[:n-1], route[n-1]
		req.Headers.Set(route)
		req.URI = last.URI
		return p.done, nil
	}
	if maddr, found := p.hasMAddr(req.URI); found {
		if p.isResponsibleFor(maddr) && p.samePortAndTransport(req, maddr) {
			req.URI = removeMaddr(req.URI)
		}
	}
	routes := req.Headers.Route()
	if len(routes) >= 1 && routes[0].URI == p.URI {
		req.Headers.Set(routes[1:])
	}

	return p.determineTargets, nil
}

func (p *Proxy) determineTargets(ctx context.Context, req *sip.Request, w sip.ResponseWriter) (state, error) {
	if maddr, found := p.hasMAddr(req.URI); found {
		uri, err := uri.Parse(maddr)
		if err != nil {
			return nil, fmt.Errorf("invalid URI in maddr: %w", err)
		}
		req.URI = uri
		return p.forwardRequest, nil
	}

	if todo(false) {
		// TODO: What is "responsible for"?
		// If the domain of the Request-URI indicates a domain this element is
		// not responsible for, the Request-URI MUST be placed into the target
		// set as the only target, and the element MUST proceed to the task of
		// Request Forwarding (Section 16.6).
		// targets = append(targets, req.URI)
	} else {
		targets, err := p.findTargets(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("failed to find targets: %w", err)
		}
		if len(targets) == 0 {
			if err := w.Write(ctx, sip.ResponseStatusNotFound); err != nil {
				return nil, err
			}
			return p.done, nil
		}
	}
	return p.forwardRequest, nil
}

type renderable interface {
	RenderTo(w io.Writer) error
}

func hash(hasher crypto.Hash, data ...renderable) (string, error) {
	h := hasher.New()
	for _, datum := range data {
		if err := datum.RenderTo(h); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func branch(hasher crypto.Hash, req *sip.Request) (branch string, loop string, err error) {

	_, viaHop := iterutils.IterFirst2(req.Headers.ViaHops())

	loop, err = hash(hasher,
		req.Headers.To(),
		req.Headers.From(),
		req.Headers.CallID(),
		req.URI, // TODO: BEFORE TRANSLATION
		header.Via{*viaHop},
		req.Headers.CSeq(),
		// TODO: make(sip.Headers).Append(req.Headers.Get("Proxy-Require"))
		// TODO: req.Headers.Get("Proxy-Require"),
	)
	if err != nil {
		return "", "", err
	}
	// Generate 8 random bytes (64 bits)
	b := make([]byte, 8)
	_, err = rand.Read(b)
	if err != nil {
		return "", "", err
	}

	// Prefix with magic cookie as required by RFC3261
	return sip.MagicCookie + hex.EncodeToString(b), loop, nil
}

func (p *Proxy) forwardRequest(ctx context.Context, req *sip.Request, _ sip.ResponseWriter) (state, error) {
	// TODO: Transfer the state?
	// targets = from last step
	for _, addr := range []string{"sip:127.0.0.1:1234"} {
		reqCopy := req.Clone().(*sip.Request)

		// TODO: Check params. See RFC 3261 16.6 1.
		parsedURI, err := uri.Parse(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid URI: %w", err)
		}
		reqCopy.URI = parsedURI

		if reqCopy.Headers.Has("Max-Forwards") {
			reqCopy.Headers.Set(reqCopy.Headers.MaxForwards() - 1)
		} else {
			reqCopy.Headers.Set(header.MaxForwards(70))
		}

		// Record-Route
		rroute := req.Headers.RecordRoute()
		rroute = append(header.RecordRoute{{
			URI: &uri.SIP{
				User:   uri.User("foo"),
				Addr:   uri.Host("bar"),
				Params: make(header.Values).Set("lr", ""),
			},
		}}, rroute...)
		reqCopy.Headers.Set(rroute)

		// Add additional header information.

		// Local policy. Add extra proxies that the request MUST pass?
		if todo(false) {

		}

		// Determine Next-Hop Address, Port, and Transport

		// Add a Via header field value
		brch, loop, err := branch(crypto.SHA3_256, req)
		if err != nil {
			return nil, err
		}

		// TODO: This needs to be documented, or maybe enforced (diff api per layer?)
		// In order for the trasnport to accept the request, the Via header MUST have a
		// zero Addr field.
		reqCopy.Headers.Prepend(header.Via{
			header.ViaHop{
				Transport: "UDP",
				Proto:     header.ProtoInfo{Name: "SIP", Version: "2.0"},
				Params:    make(header.Values).Set("branch", fmt.Sprintf("%s-%s", brch, loop)),
			},
		})

		// Add a Content-Length header field if necessary

		// Forward Request

		// Set timer C
		rq, err := p.Transport.GetOrDial(ctx, netip.MustParseAddrPort("127.0.0.1:1234"))
		if err != nil {
			return nil, err
		}
		err = rq.WriteRequest(ctx, reqCopy)
		if err != nil {
			return nil, err
		}
		break
	}
	return p.done, nil
}

func (p *Proxy) done(_ context.Context, _ *sip.Request, _ sip.ResponseWriter) (state, error) {
	return nil, nil
}
