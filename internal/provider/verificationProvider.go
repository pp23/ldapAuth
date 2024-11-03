package provider

type VerificationProvider interface {
	Verify(in []byte) (bool, error)
}
