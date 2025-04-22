import std;
import ipcrypt2 : IPCrypt2, IPCRYPT_KEYBYTES;

void main()
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
