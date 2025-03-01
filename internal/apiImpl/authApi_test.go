package archonauth

import (
	"net/url"
	"testing"

	"github.com/pp23/ldapAuth/internal/oauth2"
)

func TestDecodeFromBytesSuccess(t *testing.T) {
	URL, errURL := url.Parse("http://testurl:8080?state=123")
	if errURL != nil {
		t.Fatal(errURL)
	}
	obj := oauth2.AuthCode{
		ResponseType: "code",
		ClientId:     "test",
		RedirectURI:  URL,
	}
	data, err := encodeToBytes[oauth2.AuthCode](obj)
	if err != nil {
		t.Fatal(err)
	}
	out, errDecode := decodeFromBytes[oauth2.AuthCode](data)
	if errDecode != nil {
		t.Fatal(errDecode)
	}
	if out.ResponseType != obj.ResponseType {
		t.Errorf("Expected out.ResponseType %s, got %s", out.ResponseType, obj.ResponseType)
	}
	if out.ClientId != obj.ClientId {
		t.Errorf("Expected out.ClientId %s, got %s", out.ClientId, obj.ClientId)
	}
	if out.RedirectURI.String() != obj.RedirectURI.String() {
		t.Errorf("Expected out.RedirectURI %s, got %s", out.RedirectURI.String(), obj.RedirectURI.String())
	}
}
