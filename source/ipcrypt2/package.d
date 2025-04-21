module ipcrypt2;

import c.ipcrypt2c;

@("Initializes the ipcrypt2 library.") unittest
{
    import core.stdc.stdio;

    const ubyte[IPCRYPT_KEYBYTES] key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ];

    // Example IP (could be IPv4 or IPv6)
    const(char)* original_ip = "192.168.0.100"; // or "::1"

    IPCrypt ctx;
    ipcrypt_init(&ctx, &key[0]);
    // Clean up
    scope (exit)
        ipcrypt_deinit(&ctx);

    // Encrypt
    char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ip;
    ipcrypt_encrypt_ip_str(&ctx, &encrypted_ip[0], original_ip);

    // Decrypt
    char[IPCRYPT_MAX_IP_STR_BYTES] decrypted_ip;
    ipcrypt_decrypt_ip_str(&ctx, &decrypted_ip[0], &encrypted_ip[0]);

    // Print results
    printf("Original IP : %s\n", original_ip);
    printf("Encrypted IP: %s\n", encrypted_ip.ptr);
    printf("Decrypted IP: %s\n", decrypted_ip.ptr);
}
