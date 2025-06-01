// Package otp provides the Mobile OTP gRPC service.
// @title Mobile OTP API
// @version 1.0
// @description API for generating and validating one-time passwords (OTPs).
// @host localhost:8080
// @BasePath /
package get_otp

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	desc "github.com/PluT00/mobile-otp/internal/grpc/github.com/PluT00/mobile-otp/api/mobile-otp"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"io"
	"log/slog"
	"net/http"
	"unicode/utf8"
)

type (
	GetOTPRepository interface {
		GetNeedOTP(ctx context.Context, userId string) (bool, error)
		SetOTP(ctx context.Context, userId, otp string) error
		DeleteNeedOTP(ctx context.Context, userId string)
	}

	UseCase struct {
		repository GetOTPRepository
	}

	AuthVerificationResponse struct {
		Ok     bool   `json:"ok"`
		UserId string `json:"user_id"`
	}
)

func NewUseCase(repository GetOTPRepository) *UseCase {
	return &UseCase{
		repository: repository,
	}
}

func (uc *UseCase) GetOTP(ctx context.Context, req *desc.GetOTPRequest) (*desc.GetOTPResponse, error) {
	//userId, err := verifyJwtToken(ctx) // TODO: make jwtVerification service
	userId := "user"
	//if err != nil {
	//	return nil, status.Error(codes.PermissionDenied, err.Error())
	//}

	var clientPubKey = &ecdh.PublicKey{}
	curve := ecdh.P256()
	if req.GetPublicKey() != "test" {
		clientPubKeyBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid public key: %v", err)
		}

		clientPubKey, err = curve.NewPublicKey(clientPubKeyBytes)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to parse public key: %v", err)
		}
	}

	needOTP, err := uc.repository.GetNeedOTP(ctx, userId)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if !needOTP {
		return nil, status.Error(codes.NotFound, "Not found otp for that user")
	}
	uc.repository.DeleteNeedOTP(ctx, userId)

	newOtp := genOTP()
	err = uc.repository.SetOTP(ctx, userId, newOtp)

	serverPrivateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	serverPublicKey := serverPrivateKey.PublicKey()

	sharedSecret, err := serverPrivateKey.ECDH(clientPubKey)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	encryptedOTP, err := encryptAESGCM(sharedSecret, []byte(newOtp))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// Encode encrypted OTP and server public key
	encodedEncryptedOTP := base64.StdEncoding.EncodeToString(encryptedOTP)
	if !utf8.ValidString(encodedEncryptedOTP) {
		slog.Error("Base64-encoded encrypted OTP contains invalid UTF-8")
		return &desc.GetOTPResponse{Success: false}, fmt.Errorf("invalid Base64 encoding for encrypted OTP")
	}

	serverPubKeyBytes := serverPublicKey.Bytes()
	serverPubKeyBase64 := base64.StdEncoding.EncodeToString(serverPubKeyBytes)
	if !utf8.ValidString(serverPubKeyBase64) {
		slog.Error("Base64-encoded server public key contains invalid UTF-8")
		return &desc.GetOTPResponse{Success: false}, fmt.Errorf("invalid Base64 encoding for public key")
	}

	return &desc.GetOTPResponse{
		EncryptedOtp: encodedEncryptedOTP,
		PublicKey:    serverPubKeyBase64,
		Success:      true,
	}, nil
}

func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// genOTP - Генерация криптографически безопасного OTP длины установленной в конфиге
func genOTP() string {
	var dictionary string
	dictionary = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

	var bytes_rand = make([]byte, viper.GetInt("otp.len"))
	rand.Read(bytes_rand)
	for k, v := range bytes_rand {
		bytes_rand[k] = dictionary[v%byte(len(dictionary))]
	}
	return string(bytes_rand)
}

func verifyJwtToken(ctx context.Context) (string, error) {
	url := viper.GetString("jwt.verify_url")

	meta, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("no metadata found")
	}
	token, ok := meta["authorization"]
	if !ok {
		return "", errors.New("no authorization found")
	}

	jsonData := []byte(fmt.Sprintf("{\"jwt\":\"%s\"", token))

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading body:", err)
		return "", err
	}

	var data AuthVerificationResponse
	err = json.Unmarshal(body, &data)
	if err != nil {
		return "", err
	}

	if !data.Ok {
		return "", errors.New("invalid token")
	}

	return data.UserId, nil
}
