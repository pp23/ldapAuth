package mapper

import "iter"

// Calls the MapFn functors sequentially.
// Passes the output of the last functor as input of the next functor if no error occured.
// Stops and returns immediately if a MapFn returned an error.

// Implements the Mapper interface.
type SequentialMapper[K comparable, V any] struct {
	KVIter iter.Seq2[K, V]

	// Gets called with the occurred MapFn error and currently processed key/value. Continues processing when true gets returned.
	ErrorFn func(error, K, V) bool
}

// Maps the idp key/value without modification to the claim key/value
func (sm *SequentialMapper[K, V]) Map(fns ...MapFn[K, V]) iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		var err error
		var k K
		var v V
		for k2, v2 := range sm.KVIter {
			for _, fn := range fns {
				k, v, err = fn(k2, v2)
				// stop execution on error if ErrorFn doesn't return true
				if (err != nil && sm.ErrorFn == nil) ||
					(err != nil && sm.ErrorFn != nil &&
						!sm.ErrorFn(err, k2, v2)) {
					return
				}
			}
			if !yield(k, v) {
				return
			}
		}
	}
}
