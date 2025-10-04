/*
MIT License

Copyright (c) 2025 Matheus C. França

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
*/

/++
    D bindings for IPCrypt2, a simple and secure IP address obfuscation scheme.

    IPCrypt2 is a format-preserving encryption scheme for IPv4 and IPv6 addresses.
    It allows IP addresses to be encrypted while maintaining their format, making it
    suitable for logging and data retention purposes where IP addresses need to be
    pseudonymized.

    $(SECTION Features)
    $(UL
        $(LI Format-preserving encryption for both IPv4 and IPv6 addresses)
        $(LI Cryptographically secure using AES-128 as the underlying cipher)
        $(LI Preserves subnets: addresses sharing a prefix are encrypted to addresses sharing the same prefix)
        $(LI Deterministic: same input and key always produces the same output)
        $(LI Fast and constant-time operation)
    )
+/

module ipcrypt2;

/// IPCrypt2 C bindings
public import c.ipcrypt2c; // @system

/**
 * IPCrypt context, providing encryption/decryption of IP addresses.
 * Ensures proper initialization and cleanup of the underlying IPCrypt context.
 */
struct IPCrypt2
{
    private IPCrypt context; // Opaque IPCrypt context

    /**
     * Constructs an IPCrypt2 with the given 16-byte key.
     */
    this(scope const(ubyte)[] key) nothrow @nogc @safe
    {
        assert(key.length == IPCRYPT_KEYBYTES, "Invalid key length");
        () @trusted { ipcrypt_init(&context, &key[0]); }();
    }

    /// Ditto, but constructs from a hexadecimal key string.
    this(string hexKey) nothrow @nogc @safe
    {
        ubyte[IPCRYPT_KEYBYTES] key;
        assert(() @trusted {
            return ipcrypt_key_from_hex(&key[0], IPCRYPT_KEYBYTES, &hexKey[0], hexKey.length);
        }() == 0, "Invalid hex key");
        () @trusted { ipcrypt_init(&context, &key[0]); }();
    }

    /// Destructor ensures the IPCrypt context is cleaned up.
    ~this() nothrow @nogc @safe
    {
        () @trusted { ipcrypt_deinit(&context); }();
    }

    // Disable copying to prevent double-free
    @disable this(this);

    /**
     * Encrypts a 16-byte IP address (IPv4 or IPv6).
     * Params:
     *   ip16 = The 16-byte IP address to encrypt.
     * Returns: The encrypted 16-byte IP address.
     */
    ubyte[IPCRYPT_KEYBYTES] encryptIP16(scope const(ubyte)[] ip16) nothrow @nogc @safe
    {
        ubyte[IPCRYPT_KEYBYTES] result;
        result[] = ip16[0 .. IPCRYPT_KEYBYTES];
        () @trusted { ipcrypt_encrypt_ip16(&context, &result[0]); }();
        return result;
    }

    /**
     * Decrypts a 16-byte IP address (IPv4 or IPv6).
     * Params:
     *   ip16 = The 16-byte encrypted IP address.
     * Returns: The decrypted 16-byte IP address.
     */
    ubyte[IPCRYPT_KEYBYTES] decryptIP16(scope const(ubyte)[] ip16) nothrow @nogc @safe
    {
        ubyte[IPCRYPT_KEYBYTES] result;
        result[] = ip16[0 .. IPCRYPT_KEYBYTES];
        () @trusted { ipcrypt_decrypt_ip16(&context, &result[0]); }();
        return result;
    }

    /**
     * Encrypts an IP address string (IPv4 or IPv6).
     * Params:
     *   output = Buffer to store the encrypted IP string (must be at least IPCRYPT_MAX_IP_STR_BYTES).
     *   ipStr = The IP address string to encrypt.
     * Returns: The length of the encrypted IP string, or 0 on error.
     */
    size_t encryptIPStr(scope char[] output, scope const(char)[] ipStr) nothrow @safe
    {
        assert(output.length >= IPCRYPT_MAX_IP_STR_BYTES);
        return () @trusted {
            return ipcrypt_encrypt_ip_str(&context, &output[0], &ipStr[0]);
        }();
    }

    /**
     * Decrypts an encrypted IP address string.
     * Params:
     *   output = Buffer to store the decrypted IP string (must be at least IPCRYPT_MAX_IP_STR_BYTES).
     *   encryptedIPStr = The encrypted IP address string.
     * Returns: The length of the decrypted IP string, or 0 on error.
     */
    size_t decryptIPStr(scope char[] output, scope const(char)[] encryptedIPStr) nothrow @safe
    {
        assert(output.length >= IPCRYPT_MAX_IP_STR_BYTES);
        return () @trusted {
            return ipcrypt_decrypt_ip_str(&context, &output[0], &encryptedIPStr[0]);
        }();
    }

    /**
     * Non-deterministic encryption of a 16-byte IP address.
     * Params:
     *   ip16 = The 16-byte IP address to encrypt.
     *   random = 8-byte random data for non-determinism.
     * Returns: The 24-byte encrypted IP address.
     */
    ubyte[IPCRYPT_NDIP_BYTES] ndEncryptIP16(scope const(ubyte)[] ip16, scope const(ubyte)[] random) nothrow @nogc @safe
    {
        assert(random.length == IPCRYPT_TWEAKBYTES);
        ubyte[IPCRYPT_NDIP_BYTES] result;
        () @trusted {
            ipcrypt_nd_encrypt_ip16(&context, &result[0], &ip16[0], &random[0]);
        }();
        return result;
    }

    /**
     * Non-deterministic decryption of a 24-byte encrypted IP address.
     * Params:
     *   ndip = The 24-byte encrypted IP address.
     * Returns: The 16-byte decrypted IP address.
     */
    ubyte[IPCRYPT_KEYBYTES] ndDecryptIP16(scope const(ubyte)[] ndip) nothrow @nogc @safe
    {
        assert(ndip.length == IPCRYPT_NDIP_BYTES);
        ubyte[IPCRYPT_KEYBYTES] result;
        () @trusted {
            ipcrypt_nd_decrypt_ip16(&context, &result[0], &ndip[0]);
        }();
        return result;
    }

    /**
     * Non-deterministic encryption of an IP address string.
     * Params:
     *   output = Buffer to store the encrypted IP string (must be at least IPCRYPT_NDIP_STR_BYTES).
     *   ipStr = The IP address string to encrypt.
     *   random = 8-byte random data for non-determinism.
     * Returns: The length of the encrypted IP string, or 0 on error.
     */
    size_t ndEncryptIPStr(scope char[] output, scope const(char)[] ipStr, scope const(ubyte)[] random) nothrow @safe
    {
        assert(output.length >= IPCRYPT_NDIP_STR_BYTES);
        assert(random.length == IPCRYPT_TWEAKBYTES);
        return () @trusted {
            return ipcrypt_nd_encrypt_ip_str(&context, &output[0], &ipStr[0], &random[0]);
        }();
    }

    /**
     * Non-deterministic decryption of an encrypted IP address string.
     * Params:
     *   output = Buffer to store the decrypted IP string (must be at least IPCRYPT_MAX_IP_STR_BYTES).
     *   encryptedIPStr = The encrypted IP address string.
     * Returns: The length of the decrypted IP string, or 0 on error.
     */
    size_t ndDecryptIPStr(scope char[] output, scope const(char)[] encryptedIPStr) nothrow @safe
    {
        assert(output.length >= IPCRYPT_MAX_IP_STR_BYTES);
        return () @trusted {
            return ipcrypt_nd_decrypt_ip_str(&context, &output[0], &encryptedIPStr[0]);
        }();
    }

    /**
     * Converts a hexadecimal string to a non-deterministic encrypted IP address.
     * Params:
     *   hex = The hexadecimal string.
     * Returns: The non-deterministic encrypted IP address.
     */
    ubyte[IPCRYPT_NDIP_BYTES] ndipFromHex(string hex) nothrow @safe
    {
        ubyte[IPCRYPT_NDIP_BYTES] result;
        assert(() @trusted {
            return ipcrypt_ndip_from_hex(&result[0], &hex[0], hex.length);
        }() == 0, "Invalid hex string");
        return result;
    }
}

/**
 * IPCryptNDX context, providing extended encryption/decryption.
 * Ensures proper initialization and cleanup of the underlying IPCryptNDX context.
 */
struct IPCryptNDXCtx
{
    private IPCryptNDX context; // Opaque IPCryptNDX context

    /**
     * Constructs an IPCryptNDXCtx with the given 32-byte key.
     */
    this(scope const(ubyte)[] key) nothrow @nogc @safe
    {
        assert(key.length == IPCRYPT_NDX_KEYBYTES, "Invalid key length");
        assert(() @trusted { return ipcrypt_ndx_init(&context, &key[0]); }() == 0, "Initialization failed");
    }

    /// Ditto, but constructs from a hexadecimal key string.
    this(string hexKey) nothrow @nogc @safe
    {
        ubyte[IPCRYPT_NDX_KEYBYTES] key;
        assert(() @trusted {
            return ipcrypt_key_from_hex(&key[0], IPCRYPT_NDX_KEYBYTES, &hexKey[0], hexKey.length);
        }() == 0, "Invalid hex key");
        assert(() @trusted { return ipcrypt_ndx_init(&context, &key[0]); }() == 0, "Initialization failed");
    }

    /// Destructor ensures the IPCryptNDX context is cleaned up.
    ~this() nothrow @nogc @safe
    {
        () @trusted { ipcrypt_ndx_deinit(&context); }();
    }

    // Disable copying to prevent double-free
    @disable this(this);

    /**
     * Encrypts a 16-byte IP address (IPv4 or IPv6) with extended non-determinism.
     * Params:
     *   ip16 = The 16-byte IP address to encrypt.
     *   random = 16-byte random data for non-determinism.
     * Returns: The 32-byte encrypted IP address.
     */
    ubyte[IPCRYPT_NDX_NDIP_BYTES] encryptIP16(scope const(ubyte)[] ip16, scope const(ubyte)[] random) nothrow @nogc @safe
    {
        assert(random.length == IPCRYPT_NDX_TWEAKBYTES);
        ubyte[IPCRYPT_NDX_NDIP_BYTES] result;
        () @trusted {
            ipcrypt_ndx_encrypt_ip16(&context, &result[0], &ip16[0], &random[0]);
        }();
        return result;
    }

    /**
     * Decrypt a non-deterministically encrypted 16-byte IP address, previously encrypted with
     * `ipcrypt_ndx_encrypt_ip16`.
     *
     * Input is ndip, and output is written to ip16.
     */
    ubyte[IPCRYPT_KEYBYTES] decryptIP16(scope const(ubyte)[] ndip) nothrow @nogc @safe
    {
        assert(ndip.length == IPCRYPT_NDX_NDIP_BYTES);
        ubyte[IPCRYPT_KEYBYTES] result;
        () @trusted {
            ipcrypt_ndx_decrypt_ip16(&context, &result[0], &ndip[0]);
        }();
        return result;
    }

    /**
     * Encrypts an IP address string with extended non-determinism.
     * Params:
     *   output = Buffer to store the encrypted IP string (must be at least IPCRYPT_NDX_NDIP_STR_BYTES).
     *   ipStr = The IP address string to encrypt.
     *   random = 16-byte random data for non-determinism.
     * Returns: The length of the encrypted IP string, or 0 on error.
     */
    size_t encryptIPStr(scope char[] output, scope const(char)[] ipStr, scope const(ubyte)[] random) nothrow @safe
    {
        assert(output.length >= IPCRYPT_NDX_NDIP_STR_BYTES);
        assert(random.length == IPCRYPT_NDX_TWEAKBYTES);
        return () @trusted {
            return ipcrypt_ndx_encrypt_ip_str(&context, &output[0], &ipStr[0], &random[0]);
        }();
    }

    /**
     * Decrypts an encrypted IP address string.
     * Params:
     *   output = Buffer to store the decrypted IP string (must be at least IPCRYPT_MAX_IP_STR_BYTES).
     *   encryptedIPStr = The encrypted IP address string.
     * Returns: The length of the decrypted IP string, or 0 on error.
     */
    size_t decryptIPStr(scope char[] output, scope const(char)[] encryptedIPStr) nothrow @safe
    {
        assert(output.length >= IPCRYPT_MAX_IP_STR_BYTES);
        return () @trusted {
            return ipcrypt_ndx_decrypt_ip_str(&context, &output[0], &encryptedIPStr[0]);
        }();
    }

    /**
     * Converts a hexadecimal string to a non-deterministic encrypted IP address.
     * Params:
     *   hex = The hexadecimal string.
     * Returns: The non-deterministic encrypted IP address.
     */
    ubyte[IPCRYPT_NDX_NDIP_BYTES] ndipFromHex(string hex) nothrow @safe
    {
        ubyte[IPCRYPT_NDX_NDIP_BYTES] result;
        assert(() @trusted {
            return ipcrypt_ndx_ndip_from_hex(&result[0], &hex[0], hex.length);
        }() == 0, "Invalid hex string");
        return result;
    }
}

/**
 * IPCryptPFX context, providing prefix-preserving encryption/decryption.
 * Ensures proper initialization and cleanup of the underlying IPCryptPFX context.
 */
struct IPCryptPFXCtx
{
    private IPCryptPFX context; // Opaque IPCryptPFX context

    /**
     * Constructs an IPCryptPFXCtx with the given 32-byte key.
     */
    this(scope const(ubyte)[] key) nothrow @nogc @safe
    {
        assert(key.length == IPCRYPT_PFX_KEYBYTES, "Invalid key length");
        assert(() @trusted { return ipcrypt_pfx_init(&context, &key[0]); }() == 0, "Initialization failed");
    }

    /// Ditto, but constructs from a hexadecimal key string.
    this(string hexKey) nothrow @nogc @safe
    {
        ubyte[IPCRYPT_PFX_KEYBYTES] key;
        assert(() @trusted {
            return ipcrypt_key_from_hex(&key[0], IPCRYPT_PFX_KEYBYTES, &hexKey[0], hexKey.length);
        }() == 0, "Invalid hex key");
        assert(() @trusted { return ipcrypt_pfx_init(&context, &key[0]); }() == 0, "Initialization failed");
    }

    /// Destructor ensures the IPCryptPFX context is cleaned up.
    ~this() nothrow @nogc @safe
    {
        () @trusted { ipcrypt_pfx_deinit(&context); }();
    }

    // Disable copying to prevent double-free
    @disable this(this);

    /**
     * Encrypts a 16-byte IP address (IPv4 or IPv6) with prefix preservation.
     * Params:
     *   ip16 = The 16-byte IP address to encrypt.
     * Returns: The encrypted 16-byte IP address.
     */
    ubyte[IPCRYPT_KEYBYTES] encryptIP16(scope const(ubyte)[] ip16) nothrow @nogc @safe
    {
        ubyte[IPCRYPT_KEYBYTES] result;
        result[] = ip16[0 .. IPCRYPT_KEYBYTES];
        () @trusted { ipcrypt_pfx_encrypt_ip16(&context, &result[0]); }();
        return result;
    }

    /**
     * Decrypts a 16-byte IP address (IPv4 or IPv6) with prefix preservation.
     * Params:
     *   ip16 = The 16-byte encrypted IP address.
     * Returns: The decrypted 16-byte IP address.
     */
    ubyte[IPCRYPT_KEYBYTES] decryptIP16(scope const(ubyte)[] ip16) nothrow @nogc @safe
    {
        ubyte[IPCRYPT_KEYBYTES] result;
        result[] = ip16[0 .. IPCRYPT_KEYBYTES];
        () @trusted { ipcrypt_pfx_decrypt_ip16(&context, &result[0]); }();
        return result;
    }

    /**
     * Encrypts an IP address string (IPv4 or IPv6) with prefix preservation.
     * Params:
     *   output = Buffer to store the encrypted IP string (must be at least IPCRYPT_MAX_IP_STR_BYTES).
     *   ipStr = The IP address string to encrypt.
     * Returns: The length of the encrypted IP string, or 0 on error.
     */
    size_t encryptIPStr(scope char[] output, scope const(char)[] ipStr) nothrow @safe
    {
        assert(output.length >= IPCRYPT_MAX_IP_STR_BYTES);
        return () @trusted {
            return ipcrypt_pfx_encrypt_ip_str(&context, &output[0], &ipStr[0]);
        }();
    }

    /**
     * Decrypts an encrypted IP address string with prefix preservation.
     * Params:
     *   output = Buffer to store the decrypted IP string (must be at least IPCRYPT_MAX_IP_STR_BYTES).
     *   encryptedIPStr = The encrypted IP address string.
     * Returns: The length of the decrypted IP string, or 0 on error.
     */
    size_t decryptIPStr(scope char[] output, scope const(char)[] encryptedIPStr) nothrow @safe
    {
        assert(output.length >= IPCRYPT_MAX_IP_STR_BYTES);
        return () @trusted {
            return ipcrypt_pfx_decrypt_ip_str(&context, &output[0], &encryptedIPStr[0]);
        }();
    }
}

/**
 * Converts an IP address string to a 16-byte representation.
 * Params:
 *   ipStr = The IP address string (IPv4 or IPv6).
 * Returns: The 16-byte IP address.
 */
ubyte[IPCRYPT_KEYBYTES] ipStrToIP16(scope const(char)[] ipStr) nothrow @safe
{
    ubyte[IPCRYPT_KEYBYTES] result;
    assert(() @trusted { return ipcrypt_str_to_ip16(&result[0], &ipStr[0]); }() == 0, "Invalid IP string");
    return result;
}

/**
 * Converts a 16-byte IP address to a string.
 * Params:
 *   output = Buffer to store the IP string (must be at least IPCRYPT_MAX_IP_STR_BYTES).
 *   ip16 = The 16-byte IP address.
 * Returns: The length of the IP string, or 0 on error.
 */
size_t ip16ToStr(scope char[] output, scope const(ubyte)[] ip16) nothrow @safe
{
    assert(output.length >= IPCRYPT_MAX_IP_STR_BYTES);
    return () @trusted { return ipcrypt_ip16_to_str(&output[0], &ip16[0]); }();
}

/**
 * Converts a sockaddr to a 16-byte IP address.
 * Params:
 *   sa = The sockaddr structure.
 * Returns: The 16-byte IP address.
 */
ubyte[IPCRYPT_KEYBYTES] sockaddrToIP16(scope sockaddr* sa) nothrow @safe
{
    ubyte[IPCRYPT_KEYBYTES] result;
    assert(() @trusted { return ipcrypt_sockaddr_to_ip16(&result[0], sa); }() == 0, "Invalid sockaddr");
    return result;
}

/**
 * Converts a 16-byte IP address to a sockaddr_storage.
 * Params:
 *   ip16 = The 16-byte IP address.
 * Returns: The sockaddr_storage structure.
 */
sockaddr_storage ip16ToSockaddr(scope const(ubyte)[] ip16) nothrow @nogc @safe
{
    sockaddr_storage result;
    () @trusted { ipcrypt_ip16_to_sockaddr(&result, &ip16[0]); }();
    return result;
}

version (unittest)
{
    @("ip string encryption and decryption") unittest
    {
        ubyte[16] key = cast(ubyte[16]) "0123456789abcdef";

        auto crypt = IPCrypt2(key);

        string ip_str = "1.2.3.4";

        char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ip_buf;
        size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str);
        assert(encrypted_ip_len > 0);

        string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

        const string expected_encrypted_ip = "9f4:e6e1:c77e:ffe8:49ac:6a6a:9f11:620f";
        assert(expected_encrypted_ip == encrypted_ip);

        char[IPCRYPT_MAX_IP_STR_BYTES] decrypted_ip_buf;
        size_t decrypted_ip_len = crypt.decryptIPStr(decrypted_ip_buf[], encrypted_ip);
        assert(decrypted_ip_len > 0);
        string decrypted_ip_str = decrypted_ip_buf[0 .. decrypted_ip_len].idup;
        assert(ip_str == decrypted_ip_str);
    }

    @("ip string non-deterministic encryption and decryption") unittest
    {
        ubyte[16] key = cast(ubyte[16]) "0123456789abcdef";

        auto crypt = IPCrypt2(key);

        string ip_str = "1.2.3.4";
        ubyte[8] tweak = [1, 2, 3, 4, 5, 6, 7, 8];

        char[IPCRYPT_NDIP_STR_BYTES] encrypted_ip_buf;
        size_t encrypted_ip_len = crypt.ndEncryptIPStr(encrypted_ip_buf[], ip_str, tweak);
        assert(encrypted_ip_len > 0);

        string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

        const string expected_encrypted_ip = "01020304050607085f8ec3223eaa68378ba06d3bc3df0209";
        assert(expected_encrypted_ip == encrypted_ip);

        char[IPCRYPT_MAX_IP_STR_BYTES] decrypted_ip_buf;
        size_t decrypted_ip_len = crypt.ndDecryptIPStr(decrypted_ip_buf[], encrypted_ip);
        assert(decrypted_ip_len > 0);
        string decrypted_ip_str = decrypted_ip_buf[0 .. decrypted_ip_len].idup;
        assert(ip_str == decrypted_ip_str);
    }

    @("binary ip deterministic encryption and decryption") unittest
    {
        ubyte[16] expected_ip = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
        ];
        ubyte[16] key = cast(ubyte[16]) "0123456789abcdef";

        auto crypt = IPCrypt2(key);

        ubyte[16] ip = expected_ip;
        ip = crypt.encryptIP16(ip);
        ip = crypt.decryptIP16(ip);
        assert(expected_ip == ip);
    }

    @("binary ip non-deterministic encryption and decryption") unittest
    {
        ubyte[16] ip = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        ubyte[16] key = cast(ubyte[16]) "0123456789abcdef";
        ubyte[8] tweak = [1, 2, 3, 4, 5, 6, 7, 8];

        auto crypt = IPCrypt2(key);

        ubyte[24] encrypted_ip = crypt.ndEncryptIP16(ip, tweak);
        ubyte[16] decrypted_ip = crypt.ndDecryptIP16(encrypted_ip);
        assert(ip == decrypted_ip);
    }

    @("equivalence between AES and KIASU-BC with tweak=0*") unittest
    {
        ubyte[16] ip = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        ubyte[16] key = cast(ubyte[16]) "0123456789abcdef";
        ubyte[8] tweak = [0, 0, 0, 0, 0, 0, 0, 0];

        auto crypt = IPCrypt2(key);

        ubyte[24] encrypted_ip = crypt.ndEncryptIP16(ip, tweak);

        ubyte[16] encrypted_ip2 = crypt.encryptIP16(ip);

        assert(encrypted_ip[8 .. $] == encrypted_ip2);
    }

    @("binary ip NDX encryption and decryption") unittest
    {
        ubyte[16] ip = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        ubyte[32] key = cast(ubyte[32]) "0123456789abcdef1032547698badcfe";
        ubyte[16] tweak = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
        ];

        auto crypt = IPCryptNDXCtx(key);

        ubyte[32] encrypted_ip = crypt.encryptIP16(ip, tweak);
        ubyte[16] decrypted_ip = crypt.decryptIP16(encrypted_ip);
        assert(ip == decrypted_ip);
    }

    @("ip string NDX encryption and decryption") unittest
    {
        ubyte[32] key = cast(ubyte[32]) "0123456789abcdef1032547698badcfe";

        auto crypt = IPCryptNDXCtx(key);

        string ip_str = "1.2.3.4";
        ubyte[16] tweak = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
        ];

        char[IPCRYPT_NDX_NDIP_STR_BYTES] encrypted_ip_buf;
        size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str, tweak);
        assert(encrypted_ip_len > 0);

        string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

        const string expected_encrypted_ip = "0102030405060708090a0b0c0d0e0f10a472dd736f82eb599b85141580b21c40";
        assert(expected_encrypted_ip == encrypted_ip);

        char[IPCRYPT_MAX_IP_STR_BYTES] decrypted_ip_buf;
        size_t decrypted_ip_len = crypt.decryptIPStr(decrypted_ip_buf[], encrypted_ip);
        assert(decrypted_ip_len > 0);
        string decrypted_ip_str = decrypted_ip_buf[0 .. decrypted_ip_len].idup;
        assert(ip_str == decrypted_ip_str);
    }

    @("test vector for ipcrypt-deterministic") unittest
    {
        ubyte[16] key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10
        ];

        auto crypt = IPCrypt2(key);

        string ip_str = "0.0.0.0";

        char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ip_buf;
        size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str);
        assert(encrypted_ip_len > 0);

        string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

        const string expected = "bde9:6789:d353:824c:d7c6:f58a:6bd2:26eb";
        assert(expected == encrypted_ip);
    }

    @("test vector 1 for ipcrypt-nd") unittest
    {
        ubyte[16] key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10
        ];

        auto crypt = IPCrypt2(key);

        string ip_str = "0.0.0.0";
        ubyte[8] tweak = [0x08, 0xe0, 0xc2, 0x89, 0xbf, 0xf2, 0x3b, 0x7c];

        char[IPCRYPT_NDIP_STR_BYTES] encrypted_ip_buf;
        size_t encrypted_ip_len = crypt.ndEncryptIPStr(encrypted_ip_buf[], ip_str, tweak);
        assert(encrypted_ip_len > 0);

        string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

        const string expected = "08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16";
        assert(expected == encrypted_ip);
    }

    @("test vector 2 for ipcrypt-nd") unittest
    {
        ubyte[16] key = [
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89,
            0x67, 0x45, 0x23, 0x01
        ];

        auto crypt = IPCrypt2(key);

        string ip_str = "192.0.2.1";
        ubyte[8] tweak = [0x21, 0xbd, 0x18, 0x34, 0xbc, 0x08, 0x8c, 0xd2];

        char[IPCRYPT_NDIP_STR_BYTES] encrypted_ip_buf;
        size_t encrypted_ip_len = crypt.ndEncryptIPStr(encrypted_ip_buf[], ip_str, tweak);
        assert(encrypted_ip_len > 0);

        string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

        const string expected = "21bd1834bc088cd2e5e1fe55f95876e639faae2594a0caad";
        assert(expected == encrypted_ip);
    }

    @("test vector 3 for ipcrypt-nd") unittest
    {
        ubyte[16] key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
        ];

        auto crypt = IPCrypt2(key);

        string ip_str = "2001:db8::1";
        ubyte[8] tweak = [0xb4, 0xec, 0xbe, 0x30, 0xb7, 0x08, 0x98, 0xd7];

        char[IPCRYPT_NDIP_STR_BYTES] encrypted_ip_buf;
        size_t encrypted_ip_len = crypt.ndEncryptIPStr(encrypted_ip_buf[], ip_str, tweak);
        assert(encrypted_ip_len > 0);

        string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

        const string expected = "b4ecbe30b70898d7553ac8974d1b4250eafc4b0aa1f80c96";
        assert(expected == encrypted_ip);
    }

    @("test vector 1 for ipcrypt-ndx") unittest
    {
        ubyte[32] key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
            0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01
        ];

        auto crypt = IPCryptNDXCtx(key);

        string ip_str = "0.0.0.0";
        ubyte[16] tweak = [
            0x21, 0xbd, 0x18, 0x34, 0xbc, 0x08, 0x8c, 0xd2, 0xb4, 0xec, 0xbe, 0x30,
            0xb7, 0x08, 0x98, 0xd7
        ];

        char[IPCRYPT_NDX_NDIP_STR_BYTES] encrypted_ip_buf;
        size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str, tweak);
        assert(encrypted_ip_len > 0);

        string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

        const string expected = "21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5";
        assert(expected == encrypted_ip);
    }

    @("test vector 2 for ipcrypt-ndx") unittest
    {
        ubyte[32] key = [
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89,
            0x67, 0x45, 0x23, 0x01, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
        ];

        auto crypt = IPCryptNDXCtx(key);

        string ip_str = "192.0.2.1";
        ubyte[16] tweak = [
            0x08, 0xe0, 0xc2, 0x89, 0xbf, 0xf2, 0x3b, 0x7c, 0xb4, 0xec, 0xbe, 0x30,
            0xb7, 0x08, 0x98, 0xd7
        ];

        char[IPCRYPT_NDX_NDIP_STR_BYTES] encrypted_ip_buf;
        size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str, tweak);
        assert(encrypted_ip_len > 0);

        string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

        const string expected = "08e0c289bff23b7cb4ecbe30b70898d7766a533392a69edf1ad0d3ce362ba98a";
        assert(expected == encrypted_ip);
    }

    @("test vector 3 for ipcrypt-ndx") unittest
    {
        ubyte[32] key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c, 0x3c, 0x4f, 0xcf, 0x09, 0x88, 0x15, 0xf7, 0xab,
            0xa6, 0xd2, 0xae, 0x28, 0x16, 0x15, 0x7e, 0x2b
        ];

        auto crypt = IPCryptNDXCtx(key);

        string ip_str = "2001:db8::1";
        ubyte[16] tweak = [
            0x21, 0xbd, 0x18, 0x34, 0xbc, 0x08, 0x8c, 0xd2, 0xb4, 0xec, 0xbe, 0x30,
            0xb7, 0x08, 0x98, 0xd7
        ];

        char[IPCRYPT_NDX_NDIP_STR_BYTES] encrypted_ip_buf;
        size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str, tweak);
        assert(encrypted_ip_len > 0);

        string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

        const string expected = "21bd1834bc088cd2b4ecbe30b70898d76089c7e05ae30c2d10ca149870a263e4";
        assert(expected == encrypted_ip);
    }

    @("socket address conversion") unittest
    {
        // Test IPv4-mapped IPv6 address (1.2.3.4)
        ubyte[16] ipv4_mapped = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4
        ];

        sockaddr_storage sa = ip16ToSockaddr(ipv4_mapped);

        ubyte[16] ip16 = sockaddrToIP16(cast(sockaddr*)&sa);

        assert(ipv4_mapped == ip16);

        // Test IPv6 address (2001:db8::1)
        ubyte[16] ipv6 = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ];

        sa = ip16ToSockaddr(ipv6);

        ip16 = sockaddrToIP16(cast(sockaddr*)&sa);

        assert(ipv6 == ip16);
    }

    @("key from hex conversion") unittest
    {
        // Test valid 16-byte key
        string hex16 = "0123456789abcdef0123456789abcdef";
        ubyte[16] key16;
        int ret = () @trusted {
            return ipcrypt_key_from_hex(&key16[0], key16.length, &hex16[0], hex16.length);
        }();
        assert(ret == 0);
        ubyte[16] expected_key16 = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef
        ];
        assert(expected_key16 == key16);

        // Test valid 32-byte key
        string hex32 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        ubyte[32] key32;
        ret = () @trusted {
            return ipcrypt_key_from_hex(&key32[0], key32.length, &hex32[0], hex32.length);
        }();
        assert(ret == 0);
        ubyte[32] expected_key32 = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
        ];
        assert(expected_key32 == key32);

        // Test invalid hex length
        string invalid_hex = "0123456789abcdef";
        ubyte[16] key;
        ret = () @trusted {
            return ipcrypt_key_from_hex(&key[0], key.length, &invalid_hex[0], invalid_hex.length);
        }();
        assert(ret == -1);

        // Test invalid hex characters
        string invalid_chars = "0123456789abcdef0123456789abcdeg";
        ret = () @trusted {
            return ipcrypt_key_from_hex(&key[0], key.length, &invalid_chars[0], invalid_chars
                    .length);
        }();
        assert(ret == -1);
    }

    @("ipcrypt-pfx round-trip") unittest
    {
        ubyte[32] key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
            0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01
        ];

        auto crypt = IPCryptPFXCtx(key);

        // Test with IPv4 address string
        string ipv4_str = "192.168.1.100";

        char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ipv4_buf;
        size_t encrypted_ipv4_len = crypt.encryptIPStr(encrypted_ipv4_buf, ipv4_str);
        assert(encrypted_ipv4_len > 0);
        string encrypted_ipv4 = encrypted_ipv4_buf[0 .. $].idup;

        char[IPCRYPT_MAX_IP_STR_BYTES] decrypted_ipv4_buf;
        size_t decrypted_ipv4_len = crypt.decryptIPStr(decrypted_ipv4_buf, encrypted_ipv4);
        assert(decrypted_ipv4_len > 0);
        string decrypted_ipv4 = decrypted_ipv4_buf[0 .. $].idup;

        import std.algorithm.comparison : cmp;
        // import core.stdc.stdio;

        // printf("ip: |%s|\n", &ipv4_str[0]);
        // printf("encrypt: |%s|\n", &encrypted_ipv4[0]);
        // printf("decrypt: |%s|\n", &decrypted_ipv4[0]);

        assert(cmp(ipv4_str, decrypted_ipv4));

        // Test with IPv6 address string
        string ipv6_str = "2001:db8:85a3::8a2e:370:7334";

        char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ipv6_buf;
        size_t encrypted_ipv6_len = crypt.encryptIPStr(encrypted_ipv6_buf[], ipv6_str);
        assert(encrypted_ipv6_len > 0);
        string encrypted_ipv6 = encrypted_ipv6_buf[0 .. encrypted_ipv6_len].idup;

        char[IPCRYPT_MAX_IP_STR_BYTES] decrypted_ipv6_buf;
        size_t decrypted_ipv6_len = crypt.decryptIPStr(decrypted_ipv6_buf[], encrypted_ipv6);
        assert(decrypted_ipv6_len > 0);
        string decrypted_ipv6 = decrypted_ipv6_buf[0 .. decrypted_ipv6_len].idup;

        assert(ipv6_str == decrypted_ipv6);

        // Test with binary IP16 format for IPv4
        ubyte[16] ipv4_binary = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 100
        ];
        ubyte[16] original_ipv4_binary = ipv4_binary;

        ipv4_binary = crypt.encryptIP16(ipv4_binary);
        ipv4_binary = crypt.decryptIP16(ipv4_binary);

        assert(original_ipv4_binary == ipv4_binary);

        // Test with binary IP16 format for IPv6
        ubyte[16] ipv6_binary = [
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0, 0, 0, 0, 0x8a, 0x2e, 0x03, 0x70,
            0x73, 0x34
        ];
        ubyte[16] original_ipv6_binary = ipv6_binary;

        ipv6_binary = crypt.encryptIP16(ipv6_binary);
        ipv6_binary = crypt.decryptIP16(ipv6_binary);

        assert(original_ipv6_binary == ipv6_binary);
    }

    @("ipcrypt-pfx test vectors from python reference") unittest
    {
        // Test vector 1
        {
            ubyte[32] key = [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba,
                0x98, 0x76, 0x54, 0x32, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
                0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01
            ];

            auto crypt = IPCryptPFXCtx(key);

            string ip_str = "0.0.0.0";
            const string expected = "151.82.155.134";

            char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ip_buf;
            size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str);
            assert(encrypted_ip_len > 0);
            string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

            assert(expected == encrypted_ip);
        }

        // Test vector 2
        {
            ubyte[32] key = [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba,
                0x98, 0x76, 0x54, 0x32, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
                0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01
            ];

            auto crypt = IPCryptPFXCtx(key);

            string ip_str = "255.255.255.255";
            const string expected = "94.185.169.89";

            char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ip_buf;
            size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str);
            assert(encrypted_ip_len > 0);
            string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

            assert(expected == encrypted_ip);
        }

        // Test vector 3
        {
            ubyte[32] key = [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba,
                0x98, 0x76, 0x54, 0x32, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
                0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01
            ];

            auto crypt = IPCryptPFXCtx(key);

            string ip_str = "192.0.2.1";
            const string expected = "100.115.72.131";

            char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ip_buf;
            size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str);
            assert(encrypted_ip_len > 0);
            string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

            assert(expected == encrypted_ip);
        }

        // Test vector 4
        {
            ubyte[32] key = [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba,
                0x98, 0x76, 0x54, 0x32, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
                0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01
            ];

            auto crypt = IPCryptPFXCtx(key);

            string ip_str = "2001:db8::1";
            const string expected = "c180:5dd4:2587:3524:30ab:fa65:6ab6:f88";

            char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ip_buf;
            size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str);
            assert(encrypted_ip_len > 0);
            string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

            assert(expected == encrypted_ip);
        }

        // Test vector 5
        {
            ubyte[32] key = [
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
                0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xa9, 0xf5, 0xba, 0x40, 0xdb, 0x21,
                0x4c, 0x37, 0x98, 0xf2, 0xe1, 0xc2, 0x34, 0x56, 0x78, 0x9a
            ];

            auto crypt = IPCryptPFXCtx(key);

            string ip_str = "10.0.0.47";
            const string expected = "19.214.210.244";

            char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ip_buf;
            size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str);
            assert(encrypted_ip_len > 0);
            string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

            assert(expected == encrypted_ip);
        }

        // Test vector 6
        {
            ubyte[32] key = [
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
                0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xa9, 0xf5, 0xba, 0x40, 0xdb, 0x21,
                0x4c, 0x37, 0x98, 0xf2, 0xe1, 0xc2, 0x34, 0x56, 0x78, 0x9a
            ];

            auto crypt = IPCryptPFXCtx(key);

            string ip_str = "10.0.0.129";
            const string expected = "19.214.210.80";

            char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ip_buf;
            size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str);
            assert(encrypted_ip_len > 0);
            string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

            assert(expected == encrypted_ip);
        }

        // Test vector 7
        {
            ubyte[32] key = [
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
                0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xa9, 0xf5, 0xba, 0x40, 0xdb, 0x21,
                0x4c, 0x37, 0x98, 0xf2, 0xe1, 0xc2, 0x34, 0x56, 0x78, 0x9a
            ];

            auto crypt = IPCryptPFXCtx(key);

            string ip_str = "10.0.0.234";
            const string expected = "19.214.210.30";

            char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ip_buf;
            size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str);
            assert(encrypted_ip_len > 0);
            string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

            assert(expected == encrypted_ip);
        }

        // Test vector 8
        {
            ubyte[32] key = [
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
                0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xa9, 0xf5, 0xba, 0x40, 0xdb, 0x21,
                0x4c, 0x37, 0x98, 0xf2, 0xe1, 0xc2, 0x34, 0x56, 0x78, 0x9a
            ];

            auto crypt = IPCryptPFXCtx(key);

            string ip_str = "172.16.5.193";
            const string expected = "210.78.229.136";

            char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ip_buf;
            size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str);
            assert(encrypted_ip_len > 0);
            string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

            assert(expected == encrypted_ip);
        }

        // Test vector 9
        {
            ubyte[32] key = [
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
                0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xa9, 0xf5, 0xba, 0x40, 0xdb, 0x21,
                0x4c, 0x37, 0x98, 0xf2, 0xe1, 0xc2, 0x34, 0x56, 0x78, 0x9a
            ];

            auto crypt = IPCryptPFXCtx(key);

            string ip_str = "172.16.97.42";
            const string expected = "210.78.179.241";

            char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ip_buf;
            size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str);
            assert(encrypted_ip_len > 0);
            string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

            assert(expected == encrypted_ip);
        }

        // Test vector 10
        {
            ubyte[32] key = [
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
                0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xa9, 0xf5, 0xba, 0x40, 0xdb, 0x21,
                0x4c, 0x37, 0x98, 0xf2, 0xe1, 0xc2, 0x34, 0x56, 0x78, 0x9a
            ];

            auto crypt = IPCryptPFXCtx(key);

            string ip_str = "172.16.248.177";
            const string expected = "210.78.121.215";

            char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ip_buf;
            size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str);
            assert(encrypted_ip_len > 0);
            string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

            assert(expected == encrypted_ip);
        }

        // Test vector 11
        {
            ubyte[32] key = [
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
                0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xa9, 0xf5, 0xba, 0x40, 0xdb, 0x21,
                0x4c, 0x37, 0x98, 0xf2, 0xe1, 0xc2, 0x34, 0x56, 0x78, 0x9a
            ];

            auto crypt = IPCryptPFXCtx(key);

            string ip_str = "2001:db8::a5c9:4e2f:bb91:5a7d";
            const string expected = "7cec:702c:1243:f70:1956:125:b9bd:1aba";

            char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ip_buf;
            size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str);
            assert(encrypted_ip_len > 0);
            string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

            assert(expected == encrypted_ip);
        }

        // Test vector 12
        {
            ubyte[32] key = [
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
                0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xa9, 0xf5, 0xba, 0x40, 0xdb, 0x21,
                0x4c, 0x37, 0x98, 0xf2, 0xe1, 0xc2, 0x34, 0x56, 0x78, 0x9a
            ];

            auto crypt = IPCryptPFXCtx(key);

            string ip_str = "2001:db8::7234:d8f1:3c6e:9a52";
            const string expected = "7cec:702c:1243:f70:a3ef:c8e:95c1:cd0d";

            char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ip_buf;
            size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str);
            assert(encrypted_ip_len > 0);
            string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

            assert(expected == encrypted_ip);
        }

        // Test vector 13
        {
            ubyte[32] key = [
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
                0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xa9, 0xf5, 0xba, 0x40, 0xdb, 0x21,
                0x4c, 0x37, 0x98, 0xf2, 0xe1, 0xc2, 0x34, 0x56, 0x78, 0x9a
            ];

            auto crypt = IPCryptPFXCtx(key);

            string ip_str = "2001:db8::f1e0:937b:26d4:8c1a";
            const string expected = "7cec:702c:1243:f70:443c:c8e:6a62:b64d";

            char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ip_buf;
            size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str);
            assert(encrypted_ip_len > 0);
            string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

            assert(expected == encrypted_ip);
        }

        // Test vector 14
        {
            ubyte[32] key = [
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
                0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xa9, 0xf5, 0xba, 0x40, 0xdb, 0x21,
                0x4c, 0x37, 0x98, 0xf2, 0xe1, 0xc2, 0x34, 0x56, 0x78, 0x9a
            ];

            auto crypt = IPCryptPFXCtx(key);

            string ip_str = "2001:db8:3a5c::e7d1:4b9f:2c8a:f673";
            const string expected = "7cec:702c:3503:bef:e616:96bd:be33:a9b9";

            char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ip_buf;
            size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str);
            assert(encrypted_ip_len > 0);
            string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

            assert(expected == encrypted_ip);
        }

        // Test vector 15
        {
            ubyte[32] key = [
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
                0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xa9, 0xf5, 0xba, 0x40, 0xdb, 0x21,
                0x4c, 0x37, 0x98, 0xf2, 0xe1, 0xc2, 0x34, 0x56, 0x78, 0x9a
            ];

            auto crypt = IPCryptPFXCtx(key);

            string ip_str = "2001:db8:9f27::b4e2:7a3d:5f91:c8e6";
            const string expected = "7cec:702c:a504:b74e:194a:3d90:b047:2d1a";

            char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ip_buf;
            size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str);
            assert(encrypted_ip_len > 0);
            string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

            assert(expected == encrypted_ip);
        }

        // Test vector 16
        {
            ubyte[32] key = [
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
                0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xa9, 0xf5, 0xba, 0x40, 0xdb, 0x21,
                0x4c, 0x37, 0x98, 0xf2, 0xe1, 0xc2, 0x34, 0x56, 0x78, 0x9a
            ];

            auto crypt = IPCryptPFXCtx(key);

            string ip_str = "2001:db8:d8b4::193c:a5e7:8b2f:46d1";
            const string expected = "7cec:702c:f840:aa67:1b8:e84f:ac9d:77fb";

            char[IPCRYPT_MAX_IP_STR_BYTES] encrypted_ip_buf;
            size_t encrypted_ip_len = crypt.encryptIPStr(encrypted_ip_buf[], ip_str);
            assert(encrypted_ip_len > 0);
            string encrypted_ip = encrypted_ip_buf[0 .. encrypted_ip_len].idup;

            assert(expected == encrypted_ip);
        }
    }
}
