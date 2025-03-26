package archonauth_test

import (
	"maps"
	"slices"
	"testing"

	archonauth "github.com/pp23/ldapAuth/internal/apiImpl"
	"github.com/pp23/ldapAuth/pkg/mapper"
)

func TestLdapKeyJWTClaimMapFn(t *testing.T) {
	const (
		expectedLdapKey  = "cn"
		expectedClaimKey = "uid"
		expectedValue    = "TestValue"
	)
	keyMap := archonauth.LdapJWTKeyMap{
		LdapToJWTMap: map[string]string{
			expectedLdapKey: expectedClaimKey,
		},
	}
	inputMap := map[string]any{
		expectedLdapKey: expectedValue,
	}
	// TODO: Instantiating a new seqMapper with each value is probably unefficient
	//       Consider passing the input to the Map() fn and iterating over the input KVs
	//       Or pass the complete list/map of input values into the mapper and apply all map functions
	seqMapper := &mapper.SequentialMapper[string, any]{
		KVIter: maps.All(inputMap),
	}
	it2 := seqMapper.Map(keyMap.LdapKeyJWTClaimMapFn)
	outMap := maps.Collect(it2)
	if len(outMap) != 1 {
		t.Errorf("Expected exactly 1 element in map, got %d", len(outMap))
	}
	outMapKeys := slices.Collect(maps.Keys(outMap))
	if outMapKeys[0] != expectedClaimKey {
		t.Errorf("Expected mapped key %s, got %s", expectedClaimKey, outMapKeys[0])
	}
	if outMap[outMapKeys[0]] != string(expectedValue) {
		t.Errorf("Expected mapped value %s, got %s", string(expectedValue), outMap[outMapKeys[0]])
	}
}
