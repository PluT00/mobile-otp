gengrpc:
	protoc --go_out=internal/grpc/ --go_opt=paths=source_relative --go-grpc_out=internal/grpc/ --go-grpc_opt=paths=source_relative api/mobile-otp/mobile-otp.proto