package archonauth

import (
	"fmt"
	"iter"
	"maps"
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/pp23/ldapAuth/pkg/mapper"
)

// Maps LDAP attributes to JWT claims

// Defines the mapping Idp-Key -> Claim-Key
type LdapJWTKeyMap struct {
	// LDAP Attribute Name -> JWT Claim Name
	LdapToJWTMap map[string]string
}

func LdapClaimMapperFromConfig(mappings []*mapper.Mappings) *LdapJWTKeyMap {
	// TODO: Take care of ordering of mappers.
	for _, mapping := range mappings {
		if len(mapping.KeyMapping) > 0 {
			return &LdapJWTKeyMap{
				LdapToJWTMap: mapping.KeyMapping,
			}
		}
	}
	return &LdapJWTKeyMap{}
}

// maps the key of the LDAP attribute to a key of the provided LdapToJWTMap while keeping the LDAP attributes value
func (keymap *LdapJWTKeyMap) LdapKeyJWTClaimMapFn(inKey string, inValue any) (outKey string, outValue any, err error) {
	jwtKey, ok := keymap.LdapToJWTMap[inKey]
	if !ok {
		return inKey, inValue, fmt.Errorf("Key %s not found in key map. Available keys: %s", inKey, strings.Join(slices.Collect(maps.Keys(keymap.LdapToJWTMap)), ", "))
	}
	return jwtKey, inValue, nil
}

// Transform key->value LDAP Attributes to a iter.Seq2 to be used in mapper
func LdapAttributesToMap(ldapAttributesIter iter.Seq[*ldap.EntryAttribute]) iter.Seq2[string, any] {
	return func(yield func(key string, v any) bool) {
		for attr := range ldapAttributesIter {
			if !yield(attr.Name, attr.Values) {
				return
			}
		}
	}
}
