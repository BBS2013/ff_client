//go:build !linux

package tunx

func raiseAmbientCaps() []string { return nil }

func capabilitySummary() string { return "" }
