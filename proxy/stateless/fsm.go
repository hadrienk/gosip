package stateless

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"

	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/header"
	"github.com/ghettovoice/gosip/sip/uri"
)

type state func(ctx context.Context, req *sip.Request, w sip.ResponseWriter) (state, error)

type fsm struct {
	*Proxy
	targets []sip.URI
}

func (s *fsm) handleInboundRequest(ctx context.Context, req *sip.Request, w sip.ResponseWriter) (err error) {
	var next state = s.start
	for next != nil {
		fn := next
		next, err = fn(ctx, req, w)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *fsm) start(_ context.Context, _ *sip.Request, _ sip.ResponseWriter) (state, error) {
	return s.validateSyntax, nil
}

func (s *fsm) validateSyntax(ctx context.Context, req *sip.Request, w sip.ResponseWriter) (state, error) {
	// TODO: investigate if the lower layer takes care of this.
	// https://datatracker.ietf.org/doc/html/rfc3261#section-16.3
	if !req.IsValid() {
		if err := w.Write(ctx, sip.ResponseStatusBadRequest); err != nil {
			return nil, fmt.Errorf("invalid request: %w", err)
		}
	}
	return s.validateScheme, nil
}

func (s *fsm) validateScheme(ctx context.Context, req *sip.Request, w sip.ResponseWriter) (state, error) {
	var supported []string
	if s.SupportedSchemes == nil {
		supported = DefaultSupportedSchemes
	} else {
		supported = s.SupportedSchemes
	}
	if !slices.Contains(supported, uriScheme(req.URI)) {
		if err := w.Write(ctx, sip.ResponseStatusUnsupportedURIScheme); err != nil {
			return nil, fmt.Errorf("io error: %w", err)
		}
		return s.done, nil
	}
	return s.validateMaxForwards, nil
}

func (s *fsm) validateMaxForwards(ctx context.Context, req *sip.Request, w sip.ResponseWriter) (state, error) {
	if req.Headers.Has("Max-Forwards") && req.Headers.MaxForwards() == 1 {
		// TODO: Handle options?
		if err := w.Write(ctx, sip.ResponseStatusTooManyHops); err != nil {
			return nil, fmt.Errorf("io error: %w", err)
		}
		return s.done, nil
	}
	return s.validateLoop, nil
}

func (s *fsm) validateLoop(ctx context.Context, req *sip.Request, w sip.ResponseWriter) (state, error) {
	if s.DetectLoops {
		var loops []*header.ViaHop
		for _, hop := range req.Headers.ViaHops() {
			for _, tr := range s.transports {
				// TODO: figure out how to match on multiple transports.
				if hop.Addr.Equal(tr) {
					loops = append(loops, hop)
				}
			}
		}
		for _, loop := range loops {
			for _, bp := range loop.Params.Get("branch") {
				_, brloop, err := branch(crypto.SHA3_256, req)
				if err != nil {
					return nil, fmt.Errorf("failed to compute branch: %w", err)
				}
				params := strings.Split(bp, "-")
				if len(params) != 2 {
					continue
				}
				if params[1] == brloop {
					if err = w.Write(ctx, sip.ResponseStatusLoopDetected); err != nil {
						return nil, fmt.Errorf("io error: %w", err)
					}
					return s.done, nil
				}
			}
		}
	}
	return s.validateProxyRequire, nil
}

func (s *fsm) validateProxyRequire(ctx context.Context, req *sip.Request, w sip.ResponseWriter) (state, error) {
	if req.Headers.Has("Proxy-Require") {
		var unsupported header.Unsupported
		for _, feature := range req.Headers.ProxyRequire() {
			if !slices.Contains(s.SupportedFeatures, feature) {
				unsupported = append(unsupported, feature)
			}
		}
		if len(unsupported) > 0 {
			w.Headers().Set(unsupported)
			if err := w.Write(ctx, sip.ResponseStatusBadExtension); err != nil {
				return nil, fmt.Errorf("io error: %w", err)
			}
			return s.done, nil
		}
	}
	return s.validateProxyAuth, nil
}

func (s *fsm) validateProxyAuth(_ context.Context, _ *sip.Request, _ sip.ResponseWriter) (state, error) {
	if todo(false) {
		return nil, errors.New("implement me")
	}
	return s.routePreprocess, nil
}

func (s *fsm) routePreprocess(_ context.Context, req *sip.Request, _ sip.ResponseWriter) (state, error) {
	marked, err := s.isURIMarked(req, req.URI)
	if err != nil {
		return nil, fmt.Errorf("mark error: %w", err)
	} else if marked {
		last, route, ok := PopBack(req.Headers.Route())
		if !ok {
			return nil, fmt.Errorf("missing route in marked request: %w", err)
		}
		if len(route) == 0 {
			req.Headers.Del("Route")
		} else {
			req.Headers.Set(header.Route(route))
		}
		uriParam(last.URI).Clear()
		req.URI = last.URI
		return s.done, nil
	}

	if maddr, found := s.hasMAddr(req.URI); found {
		if s.isResponsibleFor(req) && s.samePortAndTransport(req, maddr) {
			req.URI = removeMaddr(req.URI)
		}
	}

	if fr, ok := First(req.Headers.Route()); ok {
		if uriAddr(fr.URI) == "127.0.0.1:9999" {
			_, route, _ := PopFront(req.Headers.Route())
			if len(route) == 0 {
				req.Headers.Del("Route")
			} else {
				req.Headers.Set(header.Route(route))
			}
		}
	}

	return s.determineTargets, nil
}

func (s *fsm) determineTargets(ctx context.Context, req *sip.Request, w sip.ResponseWriter) (state, error) {
	if maddr, found := s.hasMAddr(req.URI); found {
		uri, err := uri.Parse(maddr)
		if err != nil {
			return nil, fmt.Errorf("invalid URI in maddr: %w", err)
		}
		req.URI = uri
		return s.forwardRequest, nil
	}

	if uriAddr(req.URI) != "127.0.0.1:9999" {
		s.targets = append(s.targets, req.URI)
	} else {
		targets, err := s.findTargets(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("failed to find targets: %w", err)
		}
		if len(targets) == 0 && !(req.Method == sip.RequestMethodAck || req.Method == sip.RequestMethodCancel) {
			if err = w.Write(ctx, sip.ResponseStatusNotFound); err != nil {
				return nil, fmt.Errorf("io error: %w", err)
			}
			return s.done, nil
		}
		s.targets = targets
	}
	return s.forwardRequest, nil
}

func (s *fsm) forwardRequest(ctx context.Context, req *sip.Request, _ sip.ResponseWriter) (state, error) {
	for _, addr := range s.targets {
		reqCopy := req.Clone().(*sip.Request)

		// TODO: Check params. See RFC 3261 16.6 1.
		// parsedURI, err := uri.Parse(addr)
		// if err != nil {
		//	return nil, fmt.Errorf("invalid URI: %w", err)
		// }
		reqCopy.URI = addr

		if reqCopy.Headers.Has("Max-Forwards") {
			reqCopy.Headers.Set(reqCopy.Headers.MaxForwards() - 1)
		} else {
			reqCopy.Headers.Set(header.MaxForwards(70))
		}

		// Record-Route
		marker, err := s.marker(reqCopy)
		if err != nil {
			return nil, fmt.Errorf("mark error: %w", err)
		}
		rroute := req.Headers.RecordRoute()
		rroute = append(header.RecordRoute{{
			URI: &uri.SIP{
				Addr: uri.HostPort("127.0.0.1", 9999),
				Params: make(header.Values).
					Set("lr", "").
					Set(marker, ""),
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
			return nil, fmt.Errorf("mark error: %w", err)
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
		slog.Info(fmt.Sprintf("Forwarding request %s, %s", req.Method, req.URI), "original", req, "copy", reqCopy)
		rq, err := s.Transport.GetOrDial(ctx, netip.MustParseAddrPort(uriAddr(reqCopy.URI)))
		if err != nil {
			return nil, err
		}
		err = rq.WriteRequest(ctx, reqCopy)
		if err != nil {
			return nil, err
		}
		break
	}
	return s.done, nil
}

func (s *fsm) done(_ context.Context, _ *sip.Request, _ sip.ResponseWriter) (state, error) {
	return nil, nil
}
