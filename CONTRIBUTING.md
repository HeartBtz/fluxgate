# Contributing

Contributions are welcome through GitHub issues and pull requests.

## Development

1. Fork and clone `https://github.com/HeartBtz/fluxgate`.
2. Install the Go version declared in `go.mod`.
3. Create a focused branch and keep changes scoped to one concern.
4. Run `gofmt -w` on changed Go files and `go test -race ./...`.
5. Run `go vet ./...` and `docker compose config` when changing runtime files.
6. Open a pull request describing behavior changes, tests, and security or
   migration implications.

Integration tests require an isolated PostgreSQL database and are opt-in; see
`internal/service/postgres_integration_test.go`. Never point tests at production
or shared data.

By submitting a contribution, you agree that it is licensed under Apache-2.0.
