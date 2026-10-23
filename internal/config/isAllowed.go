package config

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/go-viper/mapstructure/v2"
)

// Action is true for allow, false for disallow.
type IsAllowed bool

func (a IsAllowed) String() string {
	if a {
		return "allow"
	}
	return "disallow"
}

// IsAllowedHook converts "allow"/"disallow" strings into Action values.
func IsAllowedHook() mapstructure.DecodeHookFunc {
	actionType := reflect.TypeOf(IsAllowed(false))

	return func(from, to reflect.Type, data any) (any, error) {
		if from.Kind() != reflect.String || to != actionType {
			return data, nil
		}
		switch strings.ToLower(strings.TrimSpace(data.(string))) {
		case "allow", "true":
			return IsAllowed(true), nil
		case "disallow", "false":
			return IsAllowed(false), nil
		default:
			return nil, fmt.Errorf("invalid action %q (allow or disallow)", data)
		}
	}
}
