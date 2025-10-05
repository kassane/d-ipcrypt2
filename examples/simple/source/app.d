import std.stdio : printf = writef;
import ipcrypt2 : IPCrypt2, IPCRYPT_KEYBYTES, IPCRYPT_MAX_IP_STR_BYTES;

void main() @safe
{
	// Test key: BCDEFGHIJKLMNOPQ
	ubyte[IPCRYPT_KEYBYTES] key = [
		0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
		0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51
	];

	// Test IPv4 address
	string original_ip = "1.1.1.1";
	char[IPCRYPT_MAX_IP_STR_BYTES] buf;

	// Passing the key to IPCrypt2
	auto crypt = IPCrypt2(key);

	// Perform encryption and decryption
	size_t encrypted_len = crypt.encryptIPStr(buf, original_ip);
	string encrypted = buf[0 .. encrypted_len].idup;
	size_t decrypted_len = crypt.decryptIPStr(buf, encrypted);
	string decrypted = buf[0 .. decrypted_len].idup;

	printf("Original IP:  %s\n", original_ip);
	printf("Encrypted IP: %s\n", encrypted);
	printf("Decrypted IP: %s\n", decrypted);
}
