package core

// Chain applies a sequence of MiddlewareDecorators to a VulnModule.
type Chain struct {
	middlewares []MiddlewareDecorator
}

func NewChain() *Chain {
	return &Chain{}
}

// Use appends a decorator to the chain.
func (c *Chain) Use(m MiddlewareDecorator) *Chain {
	c.middlewares = append(c.middlewares, m)
	return c
}

// Apply wraps the module through every decorator in order (first added = outermost).
func (c *Chain) Apply(mod VulnModule) VulnModule {
	result := mod
	for i := len(c.middlewares) - 1; i >= 0; i-- {
		result = c.middlewares[i].Wrap(result)
	}
	return result
}
