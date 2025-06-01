generate:
	protoc -I ./api -I ./api/googleapis \
		--go_out=internal/grpc/ \
		--go-grpc_out=internal/grpc/ \
		--grpc-gateway_out=internal/grpc/ \
		--openapiv2_out=internal/grpc/github.com/PluT00/mobile-otp/api/ \
		api/mobile-otp/mobile-otp.proto

get_proto_deps:
	rm -rf ./api/googleapis
	git -C ./api clone -n --depth=1 --filter=tree:0 https://github.com/googleapis/googleapis.git
	git -C ./api/googleapis sparse-checkout set --no-cone /google/api
	git -C ./api/googleapis checkout