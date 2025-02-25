# DPoP-Proof
Client-Side Flow(JWTClient) Client:

1. Generate RSA key pair.
2. Create DPoP proof for login.
3. Send login request with DPoP proof.
4. Store access token.
5. Create DPoP proof with access token hash for subsequent request.

Server-Side Flow(JWTWithDPoP) Server:
1. Validate DPoP proof structure.
2. Verify signature using public key from JWK.
3. Validate required claims.
4. Check JTI uniqueness.
5. Verify access token binding (if applicable).
6. Generate and validate nonces.
