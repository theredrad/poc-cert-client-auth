package common

import "strings"

type Scopes map[string]struct{}

func (s Scopes) Has(scope string) bool {
	_, ok := s[scope]
	return ok
}

func (s Scopes) HasAll(scopes []string) bool {
	// TODO: handle len zero
	for _, scope := range scopes {
		if _, ok := s[scope]; !ok {
			return false
		}
	}
	return true
}

func (s Scopes) String() string {
	scopes := make([]string, 0, len(s))
	for scope, _ := range s {
		scopes = append(scopes, scope)
	}
	return strings.Join(scopes, ",")
}
