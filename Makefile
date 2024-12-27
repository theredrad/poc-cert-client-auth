build:
	go build -o ./bin/cli ./cli/main.go
	go build -o ./bin/client ./client/main.go
	go build -o ./bin/server ./server/main.go
generate-credentials:
	./bin/cli create ca -p ./credentials -k 2048
	./bin/cli create client -n alice -p ./credentials -k 2048
	./bin/cli create client -n bob -p ./credentials -k 2048
	./bin/cli create certificate -c alice -s "bob.user.read bob.user.write" -p ./credentials -d "localhost" -d "bob"
	./bin/cli create certificate -c bob -s alice.user.read -p ./credentials -d "localhost" -d "bob"
	./bin/cli generate token -d bob -c alice -s "bob.user.read bob.user.write" -p ./credentials
	./bin/cli generate token -d alice -c bob -s alice.user.read -p ./credentials
benchmark-test-jwt:
	go test -run none -bench . -benchmem ./core/jwt/...
benchmark-test-cert:
	go test -run none -bench . -benchmem ./core/cert/...
run-server:
	./bin/server -host "0.0.0.0" -port 8585 -primary-name primary -path ./credentials
run-mtls-server:
	./bin/server -host "0.0.0.0" -port 8585 -primary-name primary -path ./credentials -mtls true
cert-request:
	./bin/client -client-name alice -server-addr "http://localhost:8585" -auth-method cert -path ./credentials
token-request:
	./bin/client -client-name alice -server-addr "http://localhost:8585" -auth-method token -path ./credentials
mtls-request:
	./bin/client -client-name alice -server-addr "https://localhost:8585" -auth-method mtls -path ./credentials
benchmark-server-token:
	./scripts/hey_benchmark_token.sh alice http://localhost:8585/token
benchmark-server-cert:
	./scripts/hey_benchmark_cert.sh alice http://localhost:8585/cert