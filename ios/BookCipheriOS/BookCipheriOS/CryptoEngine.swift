import Foundation

enum CryptoEngine {
    static func stubEncrypt(plaintext: String, passphrase: String) -> String {
        guard !plaintext.isEmpty, !passphrase.isEmpty else {
            return ""
        }
        return "BC2.STUB.SALT.NONCE.CORPUSHASH.\(plaintext.hashValue)"
    }

    static func stubDecrypt(token: String, passphrase: String) -> String {
        guard !token.isEmpty, !passphrase.isEmpty else {
            return ""
        }
        return "Decrypted message placeholder."
    }
}
