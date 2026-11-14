# httpsig

Request-side HTTP Message Signatures (RFC 9421) and Content-Digest (RFC 9530) over JSON snapshots.

`python -m httpsig inspect --message fixtures/messages/ok-get.json` already prints the method and signature headers. `verify` and `sign` are still stubs.

Standard library only. No Docker, no live HTTP, no third-party signing libraries.
