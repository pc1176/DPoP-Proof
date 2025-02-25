# DPoP-Proof
Client-Side Flow(JWTClient) Client:
Generate RSA key pair
Create DPoP proof for login
Send login request with DPoP proof
Store access token
Create DPoP proof with access token hash for subsequent request

Server-Side Flow(JWTWithDPoP) Server:
Validate DPoP proof structure
Verify signature using public key from JWK
Validate required claims
Check JTI uniqueness
Verify access token binding (if applicable)
Generate and validate nonces