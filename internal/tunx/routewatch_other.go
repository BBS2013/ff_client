//go:build !linux

package tunx

import "context"

func openRouteEvents(context.Context) <-chan struct{} { return nil }
