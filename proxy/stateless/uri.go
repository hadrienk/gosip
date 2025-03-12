package stateless

import (
	"net/url"

	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/uri"
)

// TODO add this to the uri interface?
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

func uriAddr(u uri.URI) string {
	switch v := u.(type) {
	case *uri.SIP:
		return v.Addr.String()
	case *uri.Tel:
		return v.String()
	case *uri.Any:
		return v.String()
	default:
		return ""
	}
}

// TODO: add this to the uri interface?
func uriParam(u sip.URI) uri.Values {
	switch v := u.(type) {
	case *uri.SIP:
		return v.Params
	case *uri.Tel:
		return v.Params
	case *uri.Any:
		p, _ := url.ParseQuery(v.RawQuery)
		return uri.Values(p)
	default:
		return nil
	}
}
