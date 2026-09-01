package tunnelcert

import "context"

// certificateContext makes the package's public operations safe for callers
// that have not yet attached a request context. The standard context APIs
// panic when passed nil, while certificate work must fail or continue through
// the normal bounded operation path rather than taking the process down.
func certificateContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
