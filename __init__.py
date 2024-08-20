"""
PKCE Generator Module
======================

Author: 70L0-0J0
Version: 1.0.0

Description:
-------------
This module provides a flexible and customizable implementation of the PKCE (Proof Key for Code Exchange) flow, an enhancement to OAuth2 authorization for public clients to securely authenticate without relying solely on client secrets. The module generates the necessary components, including code verifiers, code challenges, state, and nonce values, to ensure that OAuth2 flows are secure and compliant with PKCE standards.

The PKCE flow is especially beneficial for mobile and desktop applications where client secrets cannot be safely stored. This module supports both S256 (SHA-256 hashing) and plain text methods for code challenges, offering the flexibility to choose the desired security level.

Features:
----------
- **PKCE Compliance**: Generates code verifiers with lengths between 43 and 128 characters, ensuring compatibility with the PKCE standard.
- **Secure Hashing**: Supports the `S256` hashing method (recommended) for code challenges, along with an optional `plain` method.
- **Random State & Nonce Generation**: Generates cryptographically secure random values for state and nonce parameters.
- **Customizable Parameters**: Allows users to specify lengths for code verifiers, states, and nonces.
- **Convenient Payload Generation**: Provides a static method to generate URL-encoded OAuth2 payloads, making integration simple and efficient.

Installation:
--------------
To install this module, use `pip` to add it to your project. Simply run the following command:

```bash
pip install pkcegen

Usage Examples:
----------------
Example 1: Basic PKCE Payload Generation
-----------------------------------------
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
-----------------------------------------
Example 2: Customizing PKCE Parameters
-----------------------------------------
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
--------------------------------------
Example 3: Using PKCE with Custom Parameters and Different Methods
------------------------------------------------------------------
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
"""
import urllib.parse
import base64
import hashlib
import os

@staticmethod
def pkce(client_id: str, redirect_uri: str, scope: str, 
                          code_challenge_method: str = "S256", code_verifier_length: int = 32, 
                          state_length: int = 16, nonce_length: int = 16):
    """
    Static method to generate the PKCE payload without needing to instantiate the class.
    
    Args:
        client_id (str): Client ID for OAuth2 authentication.
        redirect_uri (str): Redirect URI after authentication.
        scope (str): Scope of the permissions being requested.
        code_challenge_method (str): The method for code challenge generation ("S256" or "plain").
        code_verifier_length (int): Length of the code verifier.
        state_length (int): Length of the state parameter.
        nonce_length (int): Length of the nonce parameter.
    
    Returns:
        Tuple[str, str]: URL-encoded payload and code verifier.
    """
    pkce_instance = PKCE(client_id, redirect_uri, scope, code_challenge_method)
    return pkce_instance._gen_p(code_verifier_length, state_length, nonce_length)

"""
The above code defines a class `PKCE` with a static method `pkce ` to generate the PKCE payload without instantiating the class.
"""
class PKCE:
    """
    Class to handle the generation of PKCE (Proof Key for Code Exchange) parameters.
    """
    def __init__(self, client_id: str, redirect_uri: str, scope: str, code_challenge_method: str = "S256"):
        """
        Initialize PKCE Generator with OAuth2 required parameters.
        
        Args:
            client_id (str): Client ID for OAuth2 authentication.
            redirect_uri (str): Redirect URI after authentication.
            scope (str): Scope of the permissions being requested.
            code_challenge_method (str): The method for code challenge generation ("S256" or "plain").
        """
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.code_challenge_method = code_challenge_method

    def _code_v(self, length: int = 32) -> str:
        """
        Generate a code verifier for PKCE.

        Args:
            length (int): Length of the code verifier (43-128).

        Returns:
            str: The generated code verifier.
        """
        if not 32 <= length <= 128:
            raise ValueError("Code verifier length must be between 43 and 128 characters.")
        
        code_verifier = base64.urlsafe_b64encode(os.urandom(length)).rstrip(b'=').decode('ascii')
        return code_verifier

    def _code_c(self, code_verifier: str) -> str:
        """
        Generate a code challenge based on the code verifier.

        Args:
            code_verifier (str): The code verifier.

        Returns:
            str: The generated code challenge.
        """
        if self.code_challenge_method == "S256":
            code_challenge = hashlib.sha256(code_verifier.encode('ascii')).digest()
            return base64.urlsafe_b64encode(code_challenge).rstrip(b'=').decode('ascii')
        elif self.code_challenge_method == "plain":
            return code_verifier
        else:
            raise ValueError("Unsupported code_challenge_method. Choose either 'S256' or 'plain'.")

    def _s(self, length: int = 16) -> str:
        """
        Generate a random state string.

        Args:
            length (int): Length of the state string.

        Returns:
            str: The generated state.
        """
        return base64.urlsafe_b64encode(os.urandom(length)).decode('ascii').rstrip('=')

    def _n(self, length: int = 16) -> str:
        """
        Generate a random nonce string.

        Args:
            length (int): Length of the nonce string.

        Returns:
            str: The generated nonce.
        """
        return base64.urlsafe_b64encode(os.urandom(length)).decode('ascii').rstrip('=')

    def _gen_p(self, code_verifier_length: int = 32, state_length: int = 16, nonce_length: int = 16):
        """
        Generate the full OAuth2 payload with PKCE parameters.

        Args:
            code_verifier_length (int): Length of the code verifier.
            state_length (int): Length of the state parameter.
            nonce_length (int): Length of the nonce parameter.

        Returns:
            Tuple[str, str]: URL-encoded payload and code verifier.
        """
        code_verifier = self._code_v(code_verifier_length)
        code_challenge = self._code_c(code_verifier)
        state = self._s(state_length)
        nonce = self._n(nonce_length)

        data = {
            "client_id": self.client_id,
            "scope": self.scope,
            "redirect_uri": self.redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": self.code_challenge_method,
            "state": state,
            "nonce": nonce
        }

        return urllib.parse.urlencode(data), code_verifier
