package provider

import "bytes"

/****** DO NOT USE IN PRODUCTION *****/

// This verification provider makes a simple equality check.
// Use it only for development purposes!

type EqualVerificationProvider struct {
	ProviderSelector
}

func (nvp *EqualVerificationProvider) Verify(in []byte) (bool, error) {
	var result bool = false
	var errResult error
	if err := nvp.Open(); err != nil {
		return false, err
	}
	if secret, err := nvp.Read(); err != nil {
		// use result vars instead of early return to close the providerSelector properly
		result = false
		errResult = err
	} else {
		result = bytes.Equal(secret, in[:])
	}
	if err := nvp.Close(); err != nil {
		return false, nil
	}
	return result, errResult
}
