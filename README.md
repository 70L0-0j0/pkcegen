# PKCE Generator Module

#### Author: 70L0-0J0

# Description

 PKCE (Proof Key for Code Exchange) Generator for OAuth2 Authentication This repository contains a flexible and customizable Python class for generating PKCE parameters required for OAuth2 authentication flows. It supports both S256 and plain code challenge methods and provides configurable options for generating code verifiers, code challenges, states, and nonces, ensuring compatibility with the PKCE standard.  Features: PKCE Compliance: Generate code verifiers between 43 and 128 characters, ensuring compliance with OAuth2 PKCE standards. Customizable Code Challenge Method: Supports both S256 (SHA-256 hashing) and plain challenge methods. Random State & Nonce Generation: Securely generate state and nonce parameters for your OAuth2 requests. URL-Encoded Payload: Easily generate the complete OAuth2 request payload with all required parameters. This implementation is ideal for developers looking to integrate secure PKCE-based OAuth2 flows into their applications, ensuring robust and flexible authentication.

# Features

 1. PKCE Compliance: Generates code verifiers with lengths between 43 and 128   characters, ensuring compatibility with the PKCE standard.
 2. Secure Hashing: Supports the S256 hashing method (recommended) for code     challenges, along with an optional plain method.
 3. Random State & Nonce Generation: Generates cryptographically secure random  values for state and nonce parameters.
 4. Customizable Parameters: Allows users to specify lengths for code   verifiers, states, and nonces.

 5. Convenient Payload Generation: Provides a static method to generate     URL-encoded OAuth2 payloads, making integration simple and efficient.

# Installation

```bash
pip install pkcegen
```
# Usage Examples

## 1: Basic PKCE Payload Generation

 This example demonstrates how to use the static method `pkce` to generate a full OAuth2 payload with PKCE parameters.

```python
# Call the static method 'pkce' from the PKCEGenerator class to generate the PKCE payload on S256 challenge method
# Provide the required parameters: client_id, redirect_uri, and scope
# Optionally, you can also specify the code_challenge_method, code_verifier_length, state_length, and nonce_length

import pkcegen

payload, code_verifier = pkcegen.pkce(
    client_id="your_client_id",         # Your OAuth2 client ID
    redirect_uri="Your Redirect URI",   # Redirect URI after authentication
    scope="Your scope"                  # OAuth2 scope of permissions
)
# Print the generated OAuth2 payload and the code verifier
print("Payload:", payload)
print("Code Verifier:", code_verifier)
```
## 2: Customizing PKCE Parameters
 This example demonstrates how to use the static method `pkce` to generate a full OAuth2 payload with customizing PKCE parameters.
```python
# Generate OAuth2 payload with customized PKCE parameters
# Use the static method 'pkce' to create the PKCE parameters with specific settings

import pkcegen

payload, code_verifier = pkcegen.pkce(
    client_id="your_client_id",         # Your OAuth2 client ID
    redirect_uri="Your Redirect URI",   # Redirect URI after authentication
    scope="Your scope",                 # OAuth2 scope of permissions
    code_challenge_method="plain",      # Use plain method instead of S256
    code_verifier_length=50,            # Custom code verifier length
    state_length=20,                    # Custom state length
    nonce_length=24                     # Custom nonce length
)

# Print the generated OAuth2 payload and the code verifier
print("Payload:", payload)
print("Code Verifier:", code_verifier)
```
## 3: Using PKCE with Custom Parameters and Different Methods

 This example demonstrates how to use the static method `pkce` to generate a full OAuth2 payload with custom PKCE parameters and different methods.
 
```python
# Generate OAuth2 payload with customized PKCE parameters using the S256 method
# The static method 'pkce' allows you to specify various parameters for PKCE generation

import pkcegen

payload, code_verifier = pkcegen.pkce(
    client_id="your_client_id",         # Replace with your actual OAuth2 client ID. This is a unique identifier for your application.
    redirect_uri="Your Redirect URI",   # Replace with the URI where users will be redirected after authentication. This should match what is registered with your OAuth2 provider.
    scope="Your scope",                 # Replace with the scope of permissions your application needs.
    code_challenge_method="S256",       # Specify the method for generating the code challenge. Here, "S256" is used, which means the code challenge will be generated using SHA-256 hashing.
    code_verifier_length=64,            # Custom length for the code verifier. A longer verifier adds more security. The length should be between 43 and 128 characters.
    state_length=32,                    # Custom length for the state parameter. A longer state can increase security by adding more entropy.
    nonce_length=32                     # Custom length for the nonce parameter. A longer nonce increases security by adding more randomness.
)

# Print the generated OAuth2 payload and the code verifier
print("Payload:", payload)
print("Code Verifier:", code_verifier)
```
# License

MIT License

Copyright (c) 2024 70L0-0j0

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
