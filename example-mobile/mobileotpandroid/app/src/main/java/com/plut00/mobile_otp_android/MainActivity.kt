package com.plut00.mobile_otp_android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.plut00.mobile_otp_android.ui.theme.MobileOTPTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MobileOTPTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    OTPScreen()
                }
            }
        }
    }
}

@Composable
fun OTPScreen(viewModel: OTPViewModel = viewModel()) {
    var ipAddress by remember { mutableStateOf(TextFieldValue("192.168.1.82")) }
    var username by remember { mutableStateOf(TextFieldValue("")) }
    var password by remember { mutableStateOf(TextFieldValue("")) }
    var passwordVisible by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text("Mobile OTP", fontSize = 24.sp, color = MaterialTheme.colorScheme.primary)

        // IP Address Input
        OutlinedTextField(
            value = ipAddress,
            onValueChange = { ipAddress = it },
            label = { Text("Server IP Address") },
            modifier = Modifier.fillMaxWidth(),
            isError = viewModel.errorOTP.value.contains("Invalid IP") || viewModel.errorLogin.value.contains("Invalid IP"),
            supportingText = { if (viewModel.errorOTP.value.contains("Invalid IP") || viewModel.errorLogin.value.contains("Invalid IP")) Text("Enter valid IPv4") }
        )

        // Login Status
        Text(
            "Status: ${if (viewModel.isLoggedIn.value) "Logged In" else "Not Logged In"}",
            color = if (viewModel.isLoggedIn.value) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
            fontSize = 16.sp
        )

        HorizontalDivider()

        // Get OTP Button
        Button(
            onClick = { viewModel.getOTP(ipAddress.text) },
            modifier = Modifier.fillMaxWidth(),
            enabled = ipAddress.text.isNotBlank() && viewModel.isLoggedIn.value
        ) {
            Text("Get OTP")
        }

        // OTP Display
        if (viewModel.otp.value.isNotBlank()) {
            Text(
                "OTP: ${viewModel.otp.value}",
                color = MaterialTheme.colorScheme.primary,
                fontSize = 18.sp
            )
        }

        // Error Message
        if (viewModel.errorOTP.value.isNotBlank()) {
            Text(
                "Error: ${viewModel.errorOTP.value}",
                color = MaterialTheme.colorScheme.error,
                fontSize = 16.sp
            )
        }

        HorizontalDivider()

        Text("Login", fontSize = 18.sp, color = MaterialTheme.colorScheme.primary)

        // Username input
        OutlinedTextField(
            value = username,
            onValueChange = { username = it },
            label = { Text("Username") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true
        )

        // Password input
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Password") },
            modifier = Modifier.fillMaxWidth(),
            visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            trailingIcon = {
                val image = if (passwordVisible) Icons.Filled.Visibility else Icons.Filled.VisibilityOff
                val description = if (passwordVisible) "Hide password" else "Show password"
                IconButton(onClick = { passwordVisible = !passwordVisible }) {
                    Icon(imageVector = image, contentDescription = description)
                }
            },
            singleLine = true
        )

        // Login Button
        Button(
            onClick = { viewModel.login(ipAddress.text, username.text, password.text) { /* No action needed */ } },
            modifier = Modifier.fillMaxWidth(),
            enabled = username.text.isNotBlank() &&
                    password.text.isNotBlank() &&
                    username.text.length >= 3 &&
                    password.text.length >= 6 &&
                    ipAddress.text.isNotBlank()
        ) {
            Text("Login")
        }

        // Error Message
        if (viewModel.errorLogin.value.isNotBlank()) {
            Text(
                "Error: ${viewModel.errorLogin.value}",
                color = MaterialTheme.colorScheme.error,
                fontSize = 16.sp
            )
        }
    }
}