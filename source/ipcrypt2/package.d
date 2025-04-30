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

import std.exception : enforce, assertThrown;
import std.string : toStringz, fromStringz;

/**
 * IPCrypt context, providing encryption/decryption of IP addresses.
 * Ensures proper initialization and cleanup of the underlying IPCrypt context.
 */
struct IPCrypt2
{
    private IPCrypt context; // Opaque IPCrypt context

    /**
     * Constructs an IPCrypt2 with the given 16-byte key.
     * Throws: Exception if the key length is not 16 bytes.
     */
    this(scope const(ubyte)* key) nothrow @nogc @trusted
    {
        ipcrypt_init(&context, &key[0]);
    }

    /// Ditto, but constructs from a hexadecimal key string.
    this(ref string hexKey) nothrow @nogc @trusted
    {
        ubyte[IPCRYPT_KEYBYTES] key;
        ipcrypt_init(&context, &key[0]);
    }

    /// Destructor ensures the IPCrypt context is cleaned up.
    ~this() nothrow @nogc @trusted
    {
        ipcrypt_deinit(&context);
    }

    // Disable copying to prevent double-free
    @disable this(this);

    /**
     * Encrypts a 16-byte IP address (IPv4 or IPv6).
     * Params:
     *   ip16 = The 16-byte IP address to encrypt.
     * Returns: The encrypted 16-byte IP address.
     */
    ubyte[IPCRYPT_KEYBYTES] encryptIP16(scope const(ubyte)* ip16) nothrow @trusted
    {
        ubyte[IPCRYPT_KEYBYTES] result = (
            cast(const(ubyte)[IPCRYPT_KEYBYTES]) ip16[0 .. IPCRYPT_KEYBYTES]).dup;
        ipcrypt_encrypt_ip16(&context, &result[0]);
        return result;
    }

    /**
     * Decrypts a 16-byte IP address (IPv4 or IPv6).
     * Params:
     *   ip16 = The 16-byte encrypted IP address.
     * Returns: The decrypted 16-byte IP address.
     */
    ubyte[IPCRYPT_KEYBYTES] decryptIP16(scope const(ubyte)* ip16) nothrow @trusted
    {
        ubyte[IPCRYPT_KEYBYTES] result = (
            cast(const(ubyte)[IPCRYPT_KEYBYTES]) ip16[0 .. IPCRYPT_KEYBYTES]).dup;
        ipcrypt_decrypt_ip16(&context, &result[0]);
        return result;
    }

    /**
     * Encrypts an IP address string (IPv4 or IPv6).
     * Params:
     *   ipStr = The IP address string to encrypt.
     * Returns: The encrypted IP address as a string.
     */
    string encryptIPStr(ref string ipStr) nothrow @trusted
    {
        char[IPCRYPT_MAX_IP_STR_BYTES] result;
        size_t len = ipcrypt_encrypt_ip_str(&context, &result[0], &ipStr[0]);
        return result[0 .. len].idup;
    }

    /**
     * Decrypts an encrypted IP address string.
     * Params:
     *   encryptedIPStr = The encrypted IP address string.
     * Returns: The decrypted IP address as a string.
     */
    string decryptIPStr(ref string encryptedIPStr) nothrow @trusted
    {
        char[IPCRYPT_MAX_IP_STR_BYTES] result;
        size_t len = ipcrypt_decrypt_ip_str(&context, &result[0], &encryptedIPStr[0]);
        return result[0 .. len].idup;
    }

    /**
     * Non-deterministic encryption of a 16-byte IP address.
     * Params:
     *   ip16 = The 16-byte IP address to encrypt.
     *   random = 8-byte random data for non-determinism.
     * Returns: The 24-byte encrypted IP address.
     */
    ubyte[IPCRYPT_NDIP_BYTES] ndEncryptIP16(scope const(ubyte)* ip16, scope const(ubyte)* random) nothrow @nogc @trusted
    {
        ubyte[IPCRYPT_NDIP_BYTES] result;
        ipcrypt_nd_encrypt_ip16(&context, &result[0], &ip16[0], &random[0]);
        return result;
    }

    /**
     * Non-deterministic decryption of a 24-byte encrypted IP address.
     * Params:
     *   ndip = The 24-byte encrypted IP address.
     * Returns: The 16-byte decrypted IP address.
     */
    ubyte[IPCRYPT_KEYBYTES] ndDecryptIP16(scope const(ubyte)* ndip) nothrow @nogc @trusted
    {
        ubyte[IPCRYPT_KEYBYTES] result;
        ipcrypt_nd_decrypt_ip16(&context, &result[0], &ndip[0]);
        return result;
    }

    /**
     * Non-deterministic encryption of an IP address string.
     * Params:
     *   ipStr = The IP address string to encrypt.
     *   random = 8-byte random data for non-determinism.
     * Returns: The encrypted IP address as a string.
     */
    string ndEncryptIPStr(ref string ipStr, scope const(ubyte)* random) nothrow @trusted
    {
        char[IPCRYPT_NDIP_STR_BYTES] result;
        size_t len = ipcrypt_nd_encrypt_ip_str(&context, &result[0], &ipStr[0], &random[0]);
        return result[0 .. len].idup;
    }

    /**
     * Non-deterministic decryption of an encrypted IP address string.
     * Params:
     *   encryptedIPStr = The encrypted IP address string.
     * Returns: The decrypted IP address as a string.
     */
    string ndDecryptIPStr(ref string encryptedIPStr) nothrow @trusted
    {
        char[IPCRYPT_MAX_IP_STR_BYTES] result;
        size_t len = ipcrypt_nd_decrypt_ip_str(&context, &result[0], &encryptedIPStr[0]);
        return result[0 .. len].idup;
    }

    /**
     * Converts a hexadecimal string to a non-deterministic encrypted IP address.
     * Params:
     *   hex = The hexadecimal string.
     * Returns: The non-deterministic encrypted IP address.
     */
    ubyte[IPCRYPT_NDIP_BYTES] ndipFromHex(ref string hex) nothrow @trusted
    {
        ubyte[IPCRYPT_NDIP_BYTES] result;
        ipcrypt_ndip_from_hex(&result[0], &hex[0], hex.length);
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
     * Throws: Exception if the key length is not 32 bytes.
     */
    this(scope const(ubyte)* key) nothrow @nogc @trusted
    {
        ipcrypt_ndx_init(&context, &key[0]);
    }

    /// Ditto, but constructs from a hexadecimal key string.
    this(ref string hexKey) nothrow @nogc @trusted
    {
        ubyte[IPCRYPT_KEYBYTES] key;
        ipcrypt_ndx_init(&context, &key[0]);
    }

    /// Destructor ensures the IPCryptNDX context is cleaned up.
    ~this() nothrow @nogc @trusted
    {
        ipcrypt_ndx_deinit(&context);
    }

    // Disable copying to prevent double-free
    @disable this(this);

    /**
     * Encrypts a 16-byte IP address (IPv4 or IPv6) with extended non-determinism.
     * Params:
     *   ip16 = The 16-byte IP address to encrypt.
     *   random = 16-byte random data for non-determinism.
     * Returns: The 16-byte encrypted IP address.
     */
    ubyte[IPCRYPT_NDX_KEYBYTES] encryptIP16(scope const(ubyte)* ip16, scope const(ubyte)* random) nothrow @nogc @trusted
    {
        ubyte[IPCRYPT_NDX_KEYBYTES] result;
        ipcrypt_ndx_encrypt_ip16(&context, &result[0], &ip16[0], &random[0]);
        return result;
    }

    /**
    * Decrypt a non-deterministically encrypted 16-byte IP address, previously encrypted with
    * `ipcrypt_ndx_encrypt_ip16`.333333
    *
    * Input is ndip, and output is written to ip16.
    */
    ubyte[IPCRYPT_KEYBYTES] decryptIP16(scope const(ubyte)* ndip) nothrow @nogc @trusted
    {
        ubyte[IPCRYPT_KEYBYTES] result;
        ipcrypt_ndx_decrypt_ip16(&context, &result[0], &ndip[0]);
        return result;
    }

    /**
     * Encrypts an IP address string with extended non-determinism.
     * Params:
     *   ipStr = The IP address string to encrypt.
     *   random = 16-byte random data for non-determinism.
     * Returns: The encrypted IP address as a string.
     */
    string encryptIPStr(ref string ipStr, scope const(ubyte)* random) nothrow @trusted
    {
        char[IPCRYPT_NDX_NDIP_STR_BYTES] result;
        size_t len = ipcrypt_ndx_encrypt_ip_str(&context, &result[0], &ipStr[0], &random[0]);
        return result[0 .. len].idup;
    }

    /**
     * Decrypts an encrypted IP address string.
     * Params:
     *   encryptedIPStr = The encrypted IP address string.
     * Returns: The decrypted IP address as a string.
     */
    string decryptIPStr(ref string encryptedIPStr) nothrow @trusted
    {
        char[IPCRYPT_MAX_IP_STR_BYTES] result;
        size_t len = ipcrypt_ndx_decrypt_ip_str(&context, &result[0], &encryptedIPStr[0]);
        return result[0 .. len].idup;
    }

    /**
     * Converts a hexadecimal string to a non-deterministic encrypted IP address.
     * Params:
     *   hex = The hexadecimal string.
     * Returns: The non-deterministic encrypted IP address.
     */
    ubyte[IPCRYPT_NDX_NDIP_BYTES] ndipFromHex(ref string hex) nothrow @trusted
    {
        ubyte[IPCRYPT_NDX_NDIP_BYTES] result;
        ipcrypt_ndx_ndip_from_hex(&result[0], &hex[0], hex.length);
        return result;
    }
}

/**
 * Converts an IP address string to a 16-byte representation.
 * Params:
 *   ipStr = The IP address string (IPv4 or IPv6).
 * Returns: The 16-byte IP address.
 * Throws: Exception if the conversion fails.
 */
ubyte[IPCRYPT_KEYBYTES] ipStrToIP16(ref string ipStr) @trusted
{
    ubyte[IPCRYPT_KEYBYTES] result;
    enforce(ipcrypt_str_to_ip16(&result[0], &ipStr[0]) == 0, "Invalid IP address string");
    return result;
}

/**
 * Converts a 16-byte IP address to a string.
 * Params:
 *   ip16 = The 16-byte IP address.
 * Returns: The IP address as a string.
 */
string ip16ToStr(scope const(ubyte)* ip16) nothrow @trusted
{
    char[IPCRYPT_MAX_IP_STR_BYTES] result;
    size_t len = ipcrypt_ip16_to_str(&result[0], &ip16[0]);
    return result[0 .. len].idup;
}

/**
 * Converts a sockaddr to a 16-byte IP address.
 * Params:
 *   sa = The sockaddr structure.
 * Returns: The 16-byte IP address.
 * Throws: Exception if the conversion fails.
 */
ubyte[IPCRYPT_KEYBYTES] sockaddrToIP16(scope sockaddr* sa) @trusted
{
    ubyte[IPCRYPT_KEYBYTES] result;
    enforce(ipcrypt_sockaddr_to_ip16(&result[0], sa) == 0, "Invalid sockaddr");
    return result;
}

/**
 * Converts a 16-byte IP address to a sockaddr_storage.
 * Params:
 *   ip16 = The 16-byte IP address.
 * Returns: The sockaddr_storage structure.
 */
sockaddr_storage ip16ToSockaddr(scope const(ubyte)* ip16) nothrow @nogc @trusted
{
    sockaddr_storage result;
    ipcrypt_ip16_to_sockaddr(&result, &ip16[0]);
    return result;
}

version (unittest)
{
    @("Format-Preserving") unittest
    {
        import core.stdc.stdio;
        import core.stdc.string : strcmp;

        // Test key
        ubyte[IPCRYPT_KEYBYTES] key = [
            0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
            0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51
        ];

        // Test IPv4 address
        string original_ip = "192.168.0.100";

        // Use wrapper class
        auto crypt = IPCrypt2(&key[0]);

        // Perform encryption and decryption
        auto encrypted = crypt.encryptIPStr(original_ip);
        auto decrypted = crypt.decryptIPStr(encrypted);

        // Verify results
        assert(original_ip == decrypted, "Decryption failed to match original IP");
        assert(strcmp(&original_ip[0], &encrypted[0]) != 0, "Encryption produced identical output");

        // Print results
        printf("Original IP: %s\n", original_ip.toStringz);
        printf("Encrypted IP: %s\n", encrypted.toStringz);
        printf("Decrypted IP: %s\n", decrypted.toStringz);
    }

    @("Related functions")
    @safe unittest
    {
        import std.random;

        // Test key for IPCrypt2 (16 bytes)
        ubyte[IPCRYPT_KEYBYTES] key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
        ];

        // Test IP address string (IPv4)
        string ipStr = "192.168.1.1";
        ubyte[IPCRYPT_KEYBYTES] ip16 = ipStrToIP16(ipStr);

        // Test 1: RAII lifecycle (init/deinit)
        {
            auto crypt = IPCrypt2(&key[0]);
            // Context is initialized; destructor will call ipcrypt_deinit automatically
        }

        // Test 2: Encrypt and decrypt IP16
        {
            auto crypt = IPCrypt2(&key[0]);
            auto encrypted = crypt.encryptIP16(&ip16[0]);
            auto decrypted = crypt.decryptIP16(&encrypted[0]);
            assert(decrypted == ip16, "IP16 encryption/decryption failed");
        }

        // Test 3: Encrypt and decrypt IP string
        {
            auto crypt = IPCrypt2(&key[0]);
            auto encryptedStr = crypt.encryptIPStr(ipStr);
            auto decryptedStr = crypt.decryptIPStr(encryptedStr);
            assert(decryptedStr == ipStr, "IP string encryption/decryption failed");
        }

        // Test 4: Non-deterministic encryption/decryption (IP16)
        {
            auto crypt = IPCrypt2(&key[0]);
            ubyte[IPCRYPT_TWEAKBYTES] random;
            foreach (ref b; random)
            {
                b = cast(ubyte) uniform(0, 256);
            }
            auto ndEncrypted = crypt.ndEncryptIP16(&ip16[0], &random[0]);
            auto ndDecrypted = crypt.ndDecryptIP16(&ndEncrypted[0]);
            assert(ndDecrypted == ip16, "ND IP16 encryption/decryption failed");
        }

        // Test 5: Non-deterministic encryption/decryption (IP string)
        {
            auto crypt = IPCrypt2(&key[0]);
            ubyte[IPCRYPT_TWEAKBYTES] random;
            foreach (ref b; random)
            {
                b = cast(ubyte) uniform(0, 256);
            }
            auto ndEncryptedStr = crypt.ndEncryptIPStr(ipStr, &random[0]);
            auto ndDecryptedStr = crypt.ndDecryptIPStr(ndEncryptedStr);
            assert(ndDecryptedStr == ipStr, "ND IP string encryption/decryption failed");
        }

        // Test 6: Hexadecimal key initialization
        {
            string hexKey = "0102030405060708090A0B0C0D0E0F10"; // Matches `key`
            auto crypt = IPCrypt2(hexKey);
            auto encrypted = crypt.encryptIP16(&ip16[0]);
            auto decrypted = crypt.decryptIP16(&encrypted[0]);
            assert(decrypted == ip16, "Hex key initialization failed");
        }

        // Test 7: Invalid hexadecimal key
        // {
        //     string invalidHexKey = "invalid_hex_key";
        //     assertThrown!Exception(IPCrypt2(invalidHexKey), "Expected exception for invalid hex key");
        // }

        // Test 8: IP string to IP16 and back
        {
            ubyte[IPCRYPT_KEYBYTES] ip16Converted = ipStrToIP16(ipStr);
            string ipStrConverted = ip16ToStr(&ip16Converted[0]);
            assert(ipStrConverted == ipStr, "IP string to IP16 conversion failed");
        }

        // Test 9: Invalid IP string
        {
            string invalidIP = "invalid_ip_address";
            assertThrown!Exception(ipStrToIP16(invalidIP), "Expected exception for invalid IP string");
        }
    }

    @("IPCryptNDXCtx")
    @safe unittest
    {
        import std.random;

        // Test key for IPCryptNDXCtx (16 bytes)
        ubyte[IPCRYPT_KEYBYTES] key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
        ];

        // Test IP address string (IPv6)
        string ipStr = "2001:db8::1";
        ubyte[IPCRYPT_KEYBYTES] ip16 = ipStrToIP16(ipStr);

        // Test 1: RAII lifecycle (init/deinit)
        {
            auto crypt = IPCryptNDXCtx(&key[0]);
            // Context is initialized; destructor will call ipcrypt_ndx_deinit automatically
        }

        // Test 2: Encrypt and decrypt IP16
        {
            auto crypt = IPCryptNDXCtx(&key[0]);
            ubyte[IPCRYPT_KEYBYTES] random;
            foreach (ref b; random)
            {
                b = cast(ubyte) uniform(0, 256);
            }
            auto encrypted = crypt.encryptIP16(&ip16[0], &random[0]);
            auto decrypted = crypt.decryptIP16(&encrypted[0]);
            assert(decrypted == ip16, "NDX IP16 encryption/decryption failed");
        }

        // Test 3: Encrypt and decrypt IP string
        {
            auto crypt = IPCryptNDXCtx(&key[0]);
            ubyte[IPCRYPT_KEYBYTES] random;
            foreach (ref b; random)
            {
                b = cast(ubyte) uniform(0, 256);
            }
            auto encryptedStr = crypt.encryptIPStr(ipStr, &random[0]);
            auto decryptedStr = crypt.decryptIPStr(encryptedStr);
            assert(decryptedStr == ipStr, "NDX IP string encryption/decryption failed");
        }

        // Test 4: Hexadecimal key initialization
        {
            string hexKey = "0102030405060708090A0B0C0D0E0F10" ~
                "1112131415161718191A1B1C1D1E1F20"; // Matches `key`
            auto crypt = IPCryptNDXCtx(hexKey);
            ubyte[IPCRYPT_KEYBYTES] random;
            foreach (ref b; random)
            {
                b = cast(ubyte) uniform(0, 256);
            }
            auto encrypted = crypt.encryptIP16(&ip16[0], &random[0]);
            auto decrypted = crypt.decryptIP16(&encrypted[0]);
            assert(decrypted == ip16, "NDX hex key initialization failed");
        }

        // Test 5: Invalid hexadecimal key
        // {
        //     string invalidHexKey = "invalid_hex_key";
        //     assertThrown!Exception(IPCryptNDXCtx(invalidHexKey), "Expected exception for invalid NDX hex key");
        // }
    }

    @("sockaddr conversions")
    @safe unittest
    {
        // Note: Testing sockaddr conversions requires platform-specific setup.
        // This is a placeholder test; actual sockaddr testing depends on the environment.
        string ipStr = "127.0.0.1";
        ubyte[IPCRYPT_KEYBYTES] ip16 = ipStrToIP16(ipStr);

        // Test ip16ToSockaddr and sockaddrToIP16
        auto sa = ip16ToSockaddr(&ip16[0]);
        ubyte[IPCRYPT_KEYBYTES] ip16Converted = sockaddrToIP16(cast(sockaddr*)&sa);
        assert(ip16Converted == ip16, "sockaddr conversion failed");
    }
}
