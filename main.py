if __name__ == '__main__':
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jwcrypto import jwk

    # Generate a new private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Convert the private key to OpenSSL format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Generate the corresponding public key
    public_key = private_key.public_key()

    # Convert the public key to OpenSSL format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Print the private and public keys
    print("Private key:")
    print(private_pem.decode('utf-8'))
    print("Public key:")
    print(public_pem.decode('utf-8'))

    # Generate a JWK from the private key
    jwk_key = jwk.JWK.from_pem(private_pem)
    print("JWK:")
    print(jwk_key.export(private_key=False))