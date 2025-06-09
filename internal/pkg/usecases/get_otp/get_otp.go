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
	"io"
	"log"
	"log/slog"
	"net/http"
	"unicode/utf8"

	"github.com/spf13/viper"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	desc "github.com/PluT00/mobile-otp/internal/grpc/github.com/PluT00/mobile-otp/api/mobile-otp"
	"github.com/PluT00/mobile-otp/internal/pkg/models"
)

type (
	GetOTPRepository interface {
		GetNeedOTP(ctx context.Context, userId string) (bool, error)
		SetOTP(ctx context.Context, userId, otp string) error
		DeleteNeedOTP(ctx context.Context, userId string)
		GetKeys(ctx context.Context, nonce int32) (*models.Keys, error)
		DeleteKeys(ctx context.Context, nonce int32)
	}

	UseCase struct {
		repository GetOTPRepository
	}

	AuthVerificationResponse struct {
		Valid  bool   `json:"valid"`
		UserId string `json:"user_id"`
		Mobile bool   `json:"mobile"`
	}

	AuthVerificationRequest struct {
		JWT string `json:"jwt"`
	}
)

func NewUseCase(repository GetOTPRepository) *UseCase {
	return &UseCase{
		repository: repository,
	}
}

func (uc *UseCase) GetOTP(ctx context.Context, req *desc.GetOTPRequest) (*desc.GetOTPResponse, error) {
	defer uc.repository.DeleteKeys(ctx, req.Nonce)

	keys, err := uc.repository.GetKeys(ctx, req.Nonce)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to get keys: %v", err)
	}

	if keys.ClientPubKey == "" || keys.ServerPrivKey == "" || keys.ServerPubKey == "" {
		slog.Error("Incomplete keys for nonce: ", req.Nonce)
		return nil, status.Errorf(codes.InvalidArgument, "incomplete keys")
	}

	// Parse server private key
	serverPrivKeyBytes, err := base64.StdEncoding.DecodeString(keys.ServerPrivKey)
	if err != nil {
		slog.Error("Failed to decode private key: ", err)
		return nil, status.Errorf(codes.Internal, "failed to decode private key: %v", err)
	}
	privKey, err := ecdh.P256().NewPrivateKey(serverPrivKeyBytes)
	if err != nil {
		slog.Error("Failed to parse private key: ", err)
		return nil, status.Errorf(codes.Internal, "failed to parse private key: %v", err)
	}

	// Parse client public key
	clientPubKeyBytes, err := base64.StdEncoding.DecodeString(keys.ClientPubKey)
	if err != nil || len(clientPubKeyBytes) != 65 || clientPubKeyBytes[0] != 0x04 {
		log.Printf("Invalid client public key: %v", err)
		return nil, status.Errorf(codes.Internal, "invalid client public key")
	}
	clientPubKey, err := ecdh.P256().NewPublicKey(clientPubKeyBytes)
	if err != nil {
		log.Printf("Failed to parse client public key: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to parse client public key: %v", err)
	}

	sharedSecret, err := privKey.ECDH(clientPubKey)
	if err != nil {
		log.Printf("Failed to compute shared secret: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to compute shared secret: %v", err)
	}

	plainJwt, err := decodeJwt(sharedSecret, req.EncryptedJwt)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to decode jwt: %v", err)
	}

	userId, err := verifyJwtToken(ctx, plainJwt)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
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

	return &desc.GetOTPResponse{
		EncryptedOtp: encodedEncryptedOTP,
		Success:      true,
	}, nil
}

func decodeJwt(sharedSecret []byte, encryptedJWT string) (string, error) {
	log.Printf("Encrypted JWT: %s", encryptedJWT)
	log.Printf("Shared Secret (Hex): %x", sharedSecret)
	jwtKey := pbkdf2.Key(sharedSecret, []byte("otp-encryption-salt"), 1000, 32, sha3.New256)
	log.Printf("JWT Key (Hex): %x", jwtKey)
	encryptedJwtBytes, err := base64.StdEncoding.DecodeString(encryptedJWT)
	if err != nil {
		log.Printf("Failed to decode encrypted JWT: %v", err)
		return "", fmt.Errorf("invalid encrypted JWT")
	}
	if len(encryptedJwtBytes) < 12 {
		log.Printf("Encrypted JWT too short")
		return "", fmt.Errorf("invalid encrypted JWT")
	}
	nonce := encryptedJwtBytes[:12]
	ciphertext := encryptedJwtBytes[12:]
	log.Printf("JWT Nonce (Hex): %x", nonce)
	cipherJwt, err := aes.NewCipher(jwtKey)
	if err != nil {
		log.Printf("Failed to create cipher for JWT: %v", err)
		return "", fmt.Errorf("server error")
	}
	gcm, err := cipher.NewGCM(cipherJwt)
	if err != nil {
		log.Printf("Failed to create GCM for JWT: %v", err)
		return "", fmt.Errorf("server error")
	}
	plainJwtBytes, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Printf("Failed to decrypt JWT: %v", err)
		return "", fmt.Errorf("invalid encrypted JWT")
	}
	log.Printf("Decrypted JWT: %s", string(plainJwtBytes))
	return string(plainJwtBytes), nil
}

func encryptAESGCM(sharedSecret, plaintext []byte) ([]byte, error) {
	// Derive key using PBKDF2 with SHA3-256
	key := pbkdf2.Key(sharedSecret, []byte("otp-encryption-salt"), 1000, 32, sha3.New256)
	slog.Info("Derived Key (Hex): %x", key)

	block, err := aes.NewCipher(key)
	if err != nil {
		slog.Error("Failed to create cipher: %v", err)
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		slog.Error("Failed to create GCM: %v", err)
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		slog.Error("Failed to generate nonce: %v", err)
		return nil, err
	}
	slog.Info("Nonce (Hex): %x", nonce)

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	slog.Info("Encrypted Data (Hex): %x, Length: %d", ciphertext, len(ciphertext))
	return ciphertext, nil
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

func verifyJwtToken(_ context.Context, jwt string) (string, error) {
	url := viper.GetString("jwt.verify_url")

	reqData := &AuthVerificationRequest{
		JWT: "Bearer " + jwt,
	}
	jsonData, err := json.Marshal(reqData)
	if err != nil {
		return "", fmt.Errorf("json marshal: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("http.NewRequest: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("io.ReadAll: %v", err)
	}

	var data AuthVerificationResponse
	err = json.Unmarshal(body, &data)
	if err != nil {
		return "", fmt.Errorf("json.Unmarshal: %v", err)
	}

	fmt.Println(data)

	if !data.Valid {
		return "", errors.New("!data.Valid: invalid token")
	}
	if !data.Mobile {
		return "", errors.New("!data.Mobile: invalid token")
	}

	return data.UserId, nil
}
