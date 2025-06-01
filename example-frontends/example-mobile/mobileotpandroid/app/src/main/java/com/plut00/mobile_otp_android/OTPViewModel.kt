package com.plut00.mobile_otp_android

import android.util.Base64
import android.util.Log
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.text.input.TextFieldValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class OTPViewModel : ViewModel() {
    val otp = mutableStateOf("")
    val validationMessage = mutableStateOf("")
    val errorOTP = mutableStateOf("")
    val errorLogin = mutableStateOf("")
    val jwt = mutableStateOf("")

    private val client = OkHttpClient()
    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()

    private val ipRegex = Regex(
        "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(:[0-9]{1,5})?$"
    )

    fun getOTP(ip: String, jwt: String) {
        viewModelScope.launch(Dispatchers.IO) {
            otp.value = ""
            validationMessage.value = ""
            errorOTP.value = ""

            if (!ip.matches(ipRegex)) {
                errorOTP.value = "Invalid IP address"
                return@launch
            }

            try {
                // Generate ECDH key pair (P-256)
                val keyPairGen = KeyPairGenerator.getInstance("EC")
                keyPairGen.initialize(ECGenParameterSpec("secp256r1"))
                val keyPair = keyPairGen.generateKeyPair()
                val publicKey = keyPair.public
                val privateKey = keyPair.private

                // Get raw public key bytes (0x04 + X + Y, 65 bytes)
                val ecPublicKey = publicKey as java.security.interfaces.ECPublicKey
                val point = ecPublicKey.w
                val x = point.affineX.toByteArray().trimLeadingZeros()
                val y = point.affineY.toByteArray().trimLeadingZeros()
                val rawPublicKey = ByteArray(65).apply {
                    this[0] = 0x04
                    System.arraycopy(x, 0, this, 1 + (32 - x.size), x.size)
                    System.arraycopy(y, 0, this, 33 + (32 - y.size), y.size)
                }

                // Encode to Base64
                val publicKeyBase64 = Base64.encodeToString(rawPublicKey, Base64.NO_WRAP)
                Log.d("OTPViewModel", "Client Public Key (Base64): $publicKeyBase64")
                Log.d("OTPViewModel", "Client Public Key Size: ${rawPublicKey.size}")

                // Send POST /get-otp
                val requestBody = JSONObject().apply {
                    put("public_key", publicKeyBase64)
                }.toString().trimIndent().toRequestBody(jsonMediaType)

                val request = Request.Builder()
                    .url("http://$ip:8080/get-otp")
                    .header("Authorization", "Bearer $jwt")
                    .post(requestBody)
                    .build()

                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        errorOTP.value = "Cannot get OTP"
                        return@launch
                    }

                    val responseBody = response.body?.string() ?: throw Exception("Empty response")
                    Log.d("OTPViewModel", "Server Response: $responseBody")
                    val json = JSONObject(responseBody)
                    if (!json.getBoolean("success")) {
                        errorOTP.value = "Cannot get OTP"
                        return@launch
                    }

                    // Decode server public key (raw format, 65 bytes)
                    val serverPubKeyBase64 = json.getString("publicKey")
                    val serverPubKeyBytes = Base64.decode(serverPubKeyBase64, Base64.DEFAULT)
                    Log.d("OTPViewModel", "Server Public Key (Base64): $serverPubKeyBase64")
                    Log.d("OTPViewModel", "Server Public Key Size: ${serverPubKeyBytes.size}")

                    if (serverPubKeyBytes.size != 65 || serverPubKeyBytes[0] != 0x04.toByte()) {
                        errorOTP.value = "Invalid server public key format"
                        return@launch
                    }

                    // Parse raw public key (X: bytes 1-32, Y: bytes 33-64)
                    val xCoord = BigInteger(1, serverPubKeyBytes.sliceArray(1..32))
                    val yCoord = BigInteger(1, serverPubKeyBytes.sliceArray(33..64))
                    val ecPoint = ECPoint(xCoord, yCoord)

                    // Get P-256 curve parameters
                    val ecSpec = ecPublicKey.params // Reuse client key params
                    val pubKeySpec = ECPublicKeySpec(ecPoint, ecSpec)
                    val keyFactory = KeyFactory.getInstance("EC")
                    val serverPubKey = keyFactory.generatePublic(pubKeySpec)

                    // Compute shared secret
                    val keyAgreement = javax.crypto.KeyAgreement.getInstance("ECDH")
                    keyAgreement.init(privateKey)
                    keyAgreement.doPhase(serverPubKey, true)
                    val sharedSecret = keyAgreement.generateSecret()

                    // Decode encrypted OTP
                    val encryptedOTPBase64 = json.getString("encryptedOtp")
                    val encryptedOTP = Base64.decode(encryptedOTPBase64, Base64.DEFAULT)
                    Log.d("OTPViewModel", "Encrypted OTP Length: ${encryptedOTP.size}")

                    // Decrypt OTP (AES-GCM, nonce is first 12 bytes)
                    val nonce = encryptedOTP.sliceArray(0 until 12)
                    val ciphertext = encryptedOTP.sliceArray(12 until encryptedOTP.size)
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    val aesKeySpec = SecretKeySpec(sharedSecret.sliceArray(0 until 32), "AES")
                    val gcmSpec = GCMParameterSpec(128, nonce)
                    cipher.init(Cipher.DECRYPT_MODE, aesKeySpec, gcmSpec)
                    val decrypted = cipher.doFinal(ciphertext)

                    otp.value = String(decrypted, StandardCharsets.UTF_8)
                }
            } catch (e: Exception) {
                errorOTP.value = e.message ?: "An error occurred"
                Log.e("OTPViewModel", "Error: ${e.message}", e)
            }
        }
    }

    fun login(ip: String, username: String, password: String) {
        viewModelScope.launch(Dispatchers.IO) {
            errorLogin.value = ""
            jwt.value = ""

            // Validate IP
            if (!ip.matches(ipRegex)) {
                errorLogin.value = "Invalid IP address"
                return@launch
            }

            try {
                // Remove port if present for login URL (auth service uses :8081)
                val ipWithoutPort = ip.split(":").first()

                // Build request body
                val requestBody = JSONObject().apply {
                    put("username", username.trim())
                    put("password", password.trim())
                }.toString().toRequestBody(jsonMediaType)

                // Send POST /login
                val request = Request.Builder()
                    .url("http://$ipWithoutPort:8081/login")
                    .post(requestBody)
                    .build()

                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        errorLogin.value = "Login failed: HTTP ${response.code}"
                        return@launch
                    }

                    val responseBody = response.body?.string() ?: throw Exception("Empty response")
                    Log.d("OTPViewModel", "Login response: $responseBody")
                    val json = JSONObject(responseBody)
                    if (!json.has("token")) {
                        errorLogin.value = "Login failed: No token in response"
                        return@launch
                    }

                    jwt.value = json.getString("token")
                }
            } catch (e: Exception) {
                errorLogin.value = "Login error: ${e.message ?: "Unknown error"}"
                Log.e("OTPViewModel", "Login error: ${e.message}", e)
            }
        }
    }
}

// Extension to remove leading zeros from byte array
private fun ByteArray.trimLeadingZeros(): ByteArray {
    var start = 0
    while (start < size && this[start] == 0.toByte()) {
        start++
    }
    return if (start == size) byteArrayOf(0) else copyOfRange(start, size)
}