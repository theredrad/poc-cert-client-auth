# Proof of Concept - Certificate-based Client Authorization
Authorization is always a challenge in the service to service call. This repository is a POC to see if we can authorize clients using certificates instead of JWT tokens. Normally, JWT tokens are used to let clients access protected resources, but what if the server that gives out those tokens isn't working? Then clients can't access what they need, which could be a big problem.

So, we're trying out a way using certificates signed by a certificate authority (here the same authorization server). This test will help us see how well it works compared to using JWT tokens.

## Tools
First, build the binaries by running this:
```make build```

### CLI
The CLI tool helps to generate credentials, including:
* CA certificate, public and private keys
* Client certificate, public and private keys
* Generate JWT token

Use `help` arg to learn more about the commands and arguments. Also you can run this to generate example credentials (CA and two clients with certificate and tokens):
```make generate-credentials```

### Server
The Server operates as an HTTP server, offering two routes each equipped with different middlewares. One middleware is responsible for authenticating requests using a valid JWT token, while the other ensures request authorization through a valid client certificate.

Run server:
```make run-server```

### Client
The client functions as an HTTP client designed for communication with the HTTP server. It requires specific parameters to transmit client credentials.

Send a request to `/token` endpoint with a valid JWT token (from `alice` client to `bob`):
```make cert-request```

Send a request to `/cert` endpoint with a valid Certificate token (from `alice` client to `bob`):
```make cert-request```

## Benchmark
### JWT Validator

Run this command to benchmark the JWT validator:
```
make benchmark-test-jwt
```

```
cpu: Intel(R) Core(TM) i5-1038NG7 CPU @ 2.00GHz
BenchmarkValidatorValidate2048KeySize-8            14559             81894 ns/op            9148 B/op         81 allocs/op
BenchmarkValidatorValidate4096KeySize-8             4652            241500 ns/op           19303 B/op         82 allocs/op
```

### Certificate Validator

Run this command to benchmark the Certificate validator:
```
make benchmark-test-cert
```

```
cpu: Intel(R) Core(TM) i5-1038NG7 CPU @ 2.00GHz
BenchmarkValidatorValidate2048KeySizeWithDecodeBase64-8            12860             90814 ns/op           11974 B/op         83 allocs/op
BenchmarkValidatorValidate2048KeySizeWithDecode-8                  13888             87566 ns/op            9797 B/op         81 allocs/op
BenchmarkValidatorValidate2048KeySize-8                            15175             78337 ns/op            5195 B/op         19 allocs/op
BenchmarkValidatorValidate4096KeySizeWithDecodeBase64-8             4177            254686 ns/op           23061 B/op         84 allocs/op
BenchmarkValidatorValidate4096KeySizeWithDecode-8                   4765            260341 ns/op           19601 B/op         82 allocs/op
BenchmarkValidatorValidate4096KeySize-8                             4522            242841 ns/op           14738 B/op         20 allocs/op
```

## HTTP Load test
To generate load using `hey` on the server for token endpoint (100,000 requests - 100 concurrent) run this command:
```make benchmark-server-token```

To generate load using `hey` on the server for certificate endpoint (100,000 requests - 100 concurrent) run this command:
```make benchmark-server-cert```
