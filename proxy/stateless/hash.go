package stateless

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"io"

	"github.com/ghettovoice/gosip/internal/iterutils"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/header"
)

const hashLength = 8

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
	return hex.EncodeToString(h.Sum(nil)[:hashLength]), nil
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
	b := make([]byte, 8)
	_, err = rand.Read(b)
	if err != nil {
		return "", "", err
	}
	// Prefix with magic cookie as required by RFC3261
	return sip.MagicCookie + hex.EncodeToString(b), loop, nil
}
