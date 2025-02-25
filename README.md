# DPoP-Proof
Client-Side Flow(JWTClient) Client:

1. Generate RSA key pair.
2. Create DPoP proof for login.
3. Send login request with DPoP proof.
4. Store access token.
5. Create DPoP proof with access token hash for subsequent request.

Server-Side Flow(JWTWithDPoP) Server:
Validate DPoP proof structure.
Verify signature using public key from JWK.
Validate required claims.
Check JTI uniqueness.
Verify access token binding (if applicable).
Generate and validate nonces.
