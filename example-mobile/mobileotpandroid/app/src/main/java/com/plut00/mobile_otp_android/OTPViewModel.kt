package com.plut00.mobile_otp_android

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.bouncycastle.crypto.digests.SHA3Digest
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.KeyParameter
import org.json.JSONObject
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.Random
import javax.crypto.SecretKey

class OTPViewModel : ViewModel() {
    val otp = mutableStateOf("")
    val validationMessage = mutableStateOf("")
    val errorOTP = mutableStateOf("")
    val errorLogin = mutableStateOf("")
    val isLoggedIn = mutableStateOf(false)

    private val client = OkHttpClient()
    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val keyAlias = "jwt_key"

    private var _jwtEncrypted: String? = null
    private val ipRegex = Regex(
        """^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(:[0-9]{1,5})?$"""
    )

    init {
        if (!keyStore.containsAlias(keyAlias)) {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            keyGenerator.init(
                KeyGenParameterSpec.Builder(
                    keyAlias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build()
            )
            keyGenerator.generateKey()
        }
    }

    private fun storeJwtInKeystore(jwt: String): Boolean {
        try {
            val key = keyStore.getKey(keyAlias, null) as SecretKey
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv
            val encrypted = cipher.doFinal(jwt.toByteArray(StandardCharsets.UTF_8))
            val encoded = Base64.encodeToString(iv + encrypted, Base64.NO_WRAP)
            _jwtEncrypted = encoded
            return true
        } catch (e: Exception) {
            Log.e("OTPViewModel", "Failed to store JWT: ${e.message}", e)
            return false
        }
    }

    private fun retrieveJwtFromKeystore(): String? {
        try {
            val encoded = _jwtEncrypted ?: return null
            val decoded = Base64.decode(encoded, Base64.NO_WRAP)
            val iv = decoded.sliceArray(0 until 12)
            val encrypted = decoded.sliceArray(12 until decoded.size)
            val key = keyStore.getKey(keyAlias, null) as SecretKey
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec)
            val decrypted = cipher.doFinal(encrypted)
            return String(decrypted, StandardCharsets.UTF_8)
        } catch (e: Exception) {
            Log.e("OTPViewModel", "Failed to retrieve JWT: ${e.message}", e)
            return null
        }
    }

    fun login(ip: String, username: String, password: String, callback: (Boolean) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            errorLogin.value = ""
            isLoggedIn.value = false
            _jwtEncrypted = null

            if (!ip.matches(ipRegex)) {
                errorLogin.value = "Invalid IP address"
                callback(false)
                return@launch
            }

            try {
                val ipWithoutPort = ip.split(":").first()
                val requestBody = JSONObject().apply {
                    put("username", username.trim())
                    put("password", password.trim())
                }.toString().toRequestBody(jsonMediaType)
                val request = Request.Builder()
                    .url("http://$ipWithoutPort:8081/login")
                    .post(requestBody)
                    .build()

                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        errorLogin.value = "Login failed: HTTP ${response.code}"
                        callback(false)
                        return@launch
                    }
                    val responseBody = response.body?.string() ?: throw Exception("Empty response")
                    Log.d("OTPViewModel", "Login response: $responseBody")
                    val json = JSONObject(responseBody)
                    if (!json.has("token")) {
                        errorLogin.value = "Login failed: No token"
                        callback(false)
                        return@launch
                    }
                    val token = json.getString("token")
                    if (storeJwtInKeystore(token)) {
                        isLoggedIn.value = true
                        callback(true)
                    } else {
                        errorLogin.value = "Failed to store JWT securely"
                        callback(false)
                    }
                }
            } catch (e: Exception) {
                errorLogin.value = "Login error: ${e.message ?: "Unknown error"}"
                Log.e("OTPViewModel", "Login error: ${e.message}", e)
                callback(false)
            }
        }
    }

    fun getOTP(ip: String) {
        viewModelScope.launch(Dispatchers.IO) {
            otp.value = ""
            validationMessage.value = ""
            errorOTP.value = ""

            if (!ip.matches(ipRegex)) {
                errorOTP.value = "Invalid IP address"
                return@launch
            }
            if (!isLoggedIn.value) {
                errorOTP.value = "Please login first"
                return@launch
            }
            val jwtToken = retrieveJwtFromKeystore()
            if (jwtToken.isNullOrEmpty()) {
                errorOTP.value = "No JWT available; please login again"
                return@launch
            }

            try {
                // Step 1: Sync Keys
                val keyPairGen = KeyPairGenerator.getInstance("EC")
                keyPairGen.initialize(ECGenParameterSpec("secp256r1"))
                val keyPair = keyPairGen.generateKeyPair()
                val privateKey = keyPair.private
                val publicKey = keyPair.public as java.security.interfaces.ECPublicKey
                val point = publicKey.w
                val x = point.affineX.toByteArray().trimLeadingZeros()
                val y = point.affineY.toByteArray().trimLeadingZeros()
                val rawPublicKey = ByteArray(65).apply {
                    this[0] = 0x04
                    System.arraycopy(x, 0, this, 1 + (32 - x.size), x.size)
                    System.arraycopy(y, 0, this, 33 + (32 - y.size), y.size)
                }
                val publicKeyBase64 = Base64.encodeToString(rawPublicKey, Base64.NO_WRAP)
                Log.d("OTPViewModel", "Client Public Key: $publicKeyBase64")

                val nonce = Random().nextInt(Int.MAX_VALUE)
                Log.d("OTPViewModel", "Nonce: $nonce")

                val syncRequestBody = JSONObject().apply {
                    put("public_key", publicKeyBase64)
                    put("nonce", nonce)
                }.toString().toRequestBody(jsonMediaType)
                val syncRequest = Request.Builder()
                    .url("http://$ip:8080/sync-keys")
                    .post(syncRequestBody)
                    .build()

                var serverPublicKey = ""
                client.newCall(syncRequest).execute().use { response ->
                    if (!response.isSuccessful) {
                        errorOTP.value = "Sync keys failed: HTTP ${response.code}"
                        return@launch
                    }
                    val responseBody = response.body?.string() ?: throw Exception("Empty response")
                    Log.d("OTPViewModel", "SyncKeys response: $responseBody")
                    val json = JSONObject(responseBody)
                    if (!json.has("publicKey")) {
                        errorOTP.value = "Sync keys failed: No public key"
                        return@launch
                    }
                    serverPublicKey = json.getString("publicKey")
                }

                // Step 2: Get OTP
                val serverPubKeyBytes = Base64.decode(serverPublicKey, Base64.NO_WRAP)
                if (serverPubKeyBytes.size != 65 || serverPubKeyBytes[0] != 0x04.toByte()) {
                    errorOTP.value = "Invalid server public key format"
                    return@launch
                }
                val xCoord = BigInteger(1, serverPubKeyBytes.sliceArray(1..32))
                val yCoord = BigInteger(1, serverPubKeyBytes.sliceArray(33..64))
                val ecPoint = ECPoint(xCoord, yCoord)
                val ecSpec = (privateKey as java.security.interfaces.ECPrivateKey).params
                val pubKeySpec = ECPublicKeySpec(ecPoint, ecSpec)
                val keyFactory = KeyFactory.getInstance("EC")
                val serverPubKey = keyFactory.generatePublic(pubKeySpec)

                val keyAgreement = javax.crypto.KeyAgreement.getInstance("ECDH")
                keyAgreement.init(privateKey)
                keyAgreement.doPhase(serverPubKey, true)
                val sharedSecret = keyAgreement.generateSecret()
                Log.d("OTPViewModel", "Shared Secret (Hex): ${sharedSecret.toHex()}")

                // Encrypt JWT
                val jwtKey = pbkdf2(sharedSecret, "otp-encryption-salt".toByteArray(StandardCharsets.UTF_8), 1000, 32)
                Log.d("OTPViewModel", "JWT Key (Hex): ${jwtKey.toHex()}")
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                val nonceBytes = ByteArray(12).also { Random().nextBytes(it) }
                Log.d("OTPViewModel", "JWT Nonce (Hex): ${nonceBytes.toHex()}")
                val jwtKeySpec = SecretKeySpec(jwtKey, "AES")
                val gcmSpec = GCMParameterSpec(128, nonceBytes)
                cipher.init(Cipher.ENCRYPT_MODE, jwtKeySpec, gcmSpec)
                val encryptedJwt = cipher.doFinal(jwtToken.toByteArray(StandardCharsets.UTF_8))
                val encryptedJwtWithNonce = nonceBytes + encryptedJwt
                val encryptedJwtBase64 = Base64.encodeToString(encryptedJwtWithNonce, Base64.NO_WRAP)
                Log.d("OTPViewModel", "Encrypted JWT: $encryptedJwtBase64")

                val otpRequestBody = JSONObject().apply {
                    put("encrypted_jwt", encryptedJwtBase64)
                    put("nonce", nonce)
                }.toString().toRequestBody(jsonMediaType)
                val otpRequest = Request.Builder()
                    .url("http://$ip:8080/get-otp")
                    .post(otpRequestBody)
                    .build()

                client.newCall(otpRequest).execute().use { response ->
                    if (!response.isSuccessful) {
                        errorOTP.value = "HTTP ${response.code}: ${response.message}"
                        return@launch
                    }
                    val responseBody = response.body?.string() ?: throw Exception("Empty response")
                    Log.d("OTPViewModel", "OTP response: $responseBody")
                    val json = JSONObject(responseBody)
                    if (!json.getBoolean("success")) {
                        errorOTP.value = "Request failed: ${json.optString("message", "Unknown error")}"
                        return@launch
                    }
                    val encryptedOTPBase64 = json.getString("encryptedOtp")
                    val encrypted = Base64.decode(encryptedOTPBase64, Base64.NO_WRAP)
                    Log.d("OTPViewModel", "Encrypted OTP Length: ${encrypted.size}")

                    val otpKey = pbkdf2(sharedSecret, "otp-encryption-salt".toByteArray(StandardCharsets.UTF_8), 1000, 32)
                    val otpNonce = encrypted.sliceArray(0 until 12)
                    val ciphertext = encrypted.sliceArray(12 until encrypted.size)
                    val otpCipher = Cipher.getInstance("AES/GCM/NoPadding")
                    val otpKeySpec = SecretKeySpec(otpKey, "AES")
                    val otpGcmSpec = GCMParameterSpec(128, otpNonce)
                    otpCipher.init(Cipher.DECRYPT_MODE, otpKeySpec, otpGcmSpec)
                    val decrypted = otpCipher.doFinal(ciphertext)
                    otp.value = String(decrypted, StandardCharsets.UTF_8)
                }
            } catch (e: Exception) {
                errorOTP.value = e.message ?: "Unknown error"
                Log.e("OTPViewModel", "Error: ${e.message}", e)
            }
        }
    }

    private fun ByteArray.trimLeadingZeros(): ByteArray {
        var start = 0
        while (start < size && this[start] == 0.toByte()) {
            start++
        }
        return if (start == size) byteArrayOf(0) else copyOfRange(start, size)
    }

    private fun ByteArray.toHex(): String {
        return joinToString("") { "%02x".format(it) }
    }

    private fun pbkdf2(password: ByteArray, salt: ByteArray, iterations: Int, keyLength: Int): ByteArray {
        try {
            val generator = PKCS5S2ParametersGenerator(SHA3Digest(256))
            generator.init(password, salt, iterations)
            val key = (generator.generateDerivedParameters(keyLength * 8) as KeyParameter).getKey()
            return key
        } catch (e: Exception) {
            Log.e("OTPViewModel", "PBKDF2 error: ${e.message}", e)
            throw e
        }
    }
}