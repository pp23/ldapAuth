package mapper

import "iter"

// Key/Value Processing Functor that gets applied on the input key/value-pair
type MapFn[K comparable, V any] func(inKey K, inValue V) (outKey K, outValue V, err error)

// Maps keys and their values from the IdP to claims in the token
type Mapper[K comparable, V any] interface {
	// Calls MapFn functions on a collection of key/value pairs
	Map(fns ...MapFn[K, V]) iter.Seq2[K, V]
}
