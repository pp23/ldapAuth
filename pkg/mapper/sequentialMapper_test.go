package mapper_test

import (
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/pp23/ldapAuth/pkg/mapper"
)

func TestSequentialMapperNoErrorFn(t *testing.T) {
	const (
		expectedKey   = "k1"
		expectedValue = "v1"
	)
	sequentialMapper := &mapper.SequentialMapper[string, []byte]{
		KVIter: maps.All(map[string][]byte{
			expectedKey: []byte(expectedValue),
		}),
	}
	it2 := sequentialMapper.Map(
		func(key string, value []byte) (string, []byte, error) {
			return key, value, nil
		},
	)
	processedMap := maps.Collect(it2)
	if len(processedMap) != 1 {
		t.Errorf("Expected exactly 1 K/V pair, got %d", len(processedMap))
	}
	if v, ok := processedMap[expectedKey]; !ok {
		t.Errorf("Expected key %s, got %s", expectedKey, slices.Collect(maps.Keys(processedMap))[0])
	} else {
		if string(v) != expectedValue {
			t.Errorf("Expected value %s, got %s", expectedValue, v)
		}
	}
}

type ErrorCtx struct {
	T        *testing.T
	Error    error
	K        string
	V        []byte
	RetValue bool
}

func (ctx *ErrorCtx) ErrorFn(err error, k string, v []byte) bool {
	ctx.T.Logf("ErrorFn called [%s, %s]: %v", k, string(v), err)
	ctx.Error = err
	ctx.K = k
	ctx.V = v
	return ctx.RetValue
}

func TestSequentialMapperErrorFnTrue(t *testing.T) {
	const (
		expectedKey   = "k1"
		expectedValue = "v1"
		expectedError = "TESTERROR"
	)
	errFn := &ErrorCtx{
		T:        t,
		RetValue: true,
	}
	sequentialMapper := &mapper.SequentialMapper[string, []byte]{
		KVIter: maps.All(map[string][]byte{
			expectedKey: []byte(expectedValue),
		}),
		ErrorFn: errFn.ErrorFn,
	}
	it2 := sequentialMapper.Map(
		func(key string, value []byte) (string, []byte, error) {
			return key, value, fmt.Errorf(expectedError)
		},
	)
	processedMap := maps.Collect(it2)
	if fmt.Sprintf("%v", errFn.Error) != expectedError {
		t.Errorf("Expected error %s, got %v", expectedError, errFn.Error)
	}
	if errFn.K != expectedKey {
		t.Errorf("Expected key %s in errorFn call, got %s", expectedKey, errFn.K)
	}
	if string(errFn.V) != expectedValue {
		t.Errorf("Expected value %s in errorFn call, got %s", expectedValue, errFn.V)
	}
	// errorFn returned true expects continued map processing
	if len(processedMap) != 1 {
		t.Errorf("Expected exactly 1 K/V pair, got %d", len(processedMap))
	}
	if v, ok := processedMap[expectedKey]; !ok {
		t.Errorf("Expected key %s, got %s", expectedKey, slices.Collect(maps.Keys(processedMap))[0])
	} else {
		if string(v) != expectedValue {
			t.Errorf("Expected value %s, got %s", expectedValue, v)
		}
	}
}

func TestSequentialMapperErrorFnFalse(t *testing.T) {
	const (
		expectedKey   = "k1"
		expectedValue = "v1"
		expectedError = "TESTERROR"
	)
	errFn := &ErrorCtx{
		T:        t,
		RetValue: false,
	}
	sequentialMapper := &mapper.SequentialMapper[string, []byte]{
		KVIter: maps.All(map[string][]byte{
			expectedKey: []byte(expectedValue),
		}),
		ErrorFn: errFn.ErrorFn,
	}
	it2 := sequentialMapper.Map(
		func(key string, value []byte) (string, []byte, error) {
			return key, value, fmt.Errorf(expectedError)
		},
	)
	processedMap := maps.Collect(it2)
	if fmt.Sprintf("%v", errFn.Error) != expectedError {
		t.Errorf("Expected error %s, got %v", expectedError, errFn.Error)
	}
	if errFn.K != expectedKey {
		t.Errorf("Expected key %s in errorFn call, got %s", expectedKey, errFn.K)
	}
	if string(errFn.V) != expectedValue {
		t.Errorf("Expected value %s in errorFn call, got %s", expectedValue, errFn.V)
	}
	// errorFn returned false expects no continued map processing
	if len(processedMap) != 0 {
		t.Errorf("Expected exactly 1 K/V pair, got %d", len(processedMap))
	}
}
