module ipcrypt2;

public import c.ipcrypt2c;

@("Format-Preserving") unittest
{
    import core.stdc.stdio;
    import core.stdc.string : strcmp;

    struct IPCryptScope
    {
        private IPCrypt ctx;

        this(const ubyte* key)
        {
            ipcrypt_init(&ctx, key);
        }

        ~this()
        {
            ipcrypt_deinit(&ctx);
        }

        char[IPCRYPT_MAX_IP_STR_BYTES] encrypt(const char* ip)
        {
            char[IPCRYPT_MAX_IP_STR_BYTES] result;
            ipcrypt_encrypt_ip_str(&ctx, &result[0], ip);
            return result;
        }

        char[IPCRYPT_MAX_IP_STR_BYTES] decrypt(const char* ip)
        {
            char[IPCRYPT_MAX_IP_STR_BYTES] result;
            ipcrypt_decrypt_ip_str(&ctx, &result[0], ip);
            return result;
        }
    }

    // Test key
    const ubyte[IPCRYPT_KEYBYTES] key = [
        0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
        0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51
    ];

    // Test IPv6 address
    string original_ip = "2001:db8::1";

    // Use RAII wrapper
    auto cryptor = IPCryptScope(&key[0]);

    // Perform encryption and decryption
    auto encrypted = cryptor.encrypt(&original_ip[0]);
    auto decrypted = cryptor.decrypt(&encrypted[0]);

    // Verify results
    assert(strcmp(&original_ip[0], &decrypted[0]) == 0, "Decryption failed to match original IP");
    assert(strcmp(&original_ip[0], &encrypted[0]) != 0, "Encryption produced identical output");

    // Print results
    printf("Original IPv6: %s\n", &original_ip[0]);
    printf("Encrypted IPv6: %s\n", &encrypted[0]);
    printf("Decrypted IPv6: %s\n", &decrypted[0]);
}
