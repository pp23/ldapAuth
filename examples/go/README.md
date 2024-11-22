## example-go-oauth2

Uses the golang.org/x/oauth2 package to retrieve an access token.

### build

`make`

### run

`CLIENT_SECRET="" bin/example-go-oauth2`

- The example app asks for requesting the authcode first. This can be done with curl:
  ```
  curl -v -u "<USER>:<TESTSECRET>" 'http://localhost:3000/auth?response_type=code&client_id=client&redirect_uri=http://localhost:3000/token&scope=r&code_challenge=a'
  ```
- The response contains the authcode in the redirect location:
  ```
  < HTTP/1.1 307 Temporary Redirect
  < Location: http://localhost:3000/token?code=abc
  < Date: Fri, 22 Nov 2024 21:43:52 GMT
  < Content-Length: 0
  ```
- Type in the authcode `abc` when the `example-go-oauth2` applications asks for it
- The Access Token should get requested and printed out
