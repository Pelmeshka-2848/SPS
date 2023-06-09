#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <openssl/evp.h>
#include <openssl/rand.h>

class PasswordManager {
private:
    std::string filePath;
    std::string masterPassword;

public:
    PasswordManager(const std::string& filePath, const std::string& masterPassword)
        : filePath(filePath), masterPassword(masterPassword) {}

    void SavePassword(const std::string& website, const std::string& username, const std::string& password) {
        std::map<std::string, std::string> passwords = LoadPasswords();
        passwords[website] = EncryptString(password, masterPassword);
        SavePasswords(passwords);
    }

    std::string GetPassword(const std::string& website) {
        std::map<std::string, std::string> passwords = LoadPasswords();
        if (passwords.count(website) > 0) {
            return DecryptString(passwords[website], masterPassword);
        }
        return "";
    }

private:
    std::map<std::string, std::string> LoadPasswords() {
        std::map<std::string, std::string> passwords;

        std::ifstream inputFile(filePath);
        if (inputFile.is_open()) {
            std::string line;
            while (std::getline(inputFile, line)) {
                size_t separatorIndex = line.find(':');
                if (separatorIndex != std::string::npos) {
                    std::string website = line.substr(0, separatorIndex);
                    std::string encryptedPassword = line.substr(separatorIndex + 1);
                    passwords[website] = encryptedPassword;
                }
            }
            inputFile.close();
        }

        return passwords;
    }

    void SavePasswords(const std::map<std::string, std::string>& passwords) {
        std::ofstream outputFile(filePath);
        if (outputFile.is_open()) {
            for (const auto& pair : passwords) {
                outputFile << pair.first << ':' << pair.second << '\n';
            }
            outputFile.close();
        }
    }

    std::string EncryptString(const std::string& plainText, const std::string& password) {
        // Используем OpenSSL EVP для шифрования строки
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX_init(ctx);

        const EVP_CIPHER* cipher = EVP_aes_256_cbc();
        unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
        unsigned char encryptedData[plainText.length() + EVP_MAX_BLOCK_LENGTH];
        int encryptedLength = 0;

        RAND_bytes(iv, EVP_CIPHER_iv_length(cipher));
        EVP_BytesToKey(cipher, EVP_sha256(), nullptr, reinterpret_cast<const unsigned char*>(password.c_str()), password.length(), 1, key, iv);

        EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv);
        EVP_EncryptUpdate(ctx, encryptedData, &encryptedLength, reinterpret_cast<const unsigned char*>(plainText.c_str()), plainText.length());
        int finalEncryptedLength = 0;
        EVP_EncryptFinal_ex(ctx, encryptedData + encryptedLength, &finalEncryptedLength);
        encryptedLength += finalEncryptedLength;

        EVP_CIPHER_CTX_cleanup(ctx);
        EVP_CIPHER_CTX_free(ctx);

        std::string encryptedString(reinterpret_cast<char*>(encryptedData), encryptedLength);
        std::string encodedIV(reinterpret_cast<char*>(iv), EVP_CIPHER_iv_length(cipher));

        return encodedIV + encryptedString;
    }

    std::string DecryptString(const std::string& encryptedText, const std::string& password) {
        // Используем OpenSSL EVP для расшифровки строки
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX_init(ctx);

        const EVP_CIPHER* cipher = EVP_aes_256_cbc();
        unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
        unsigned char decryptedData[encryptedText.length() - EVP_MAX_IV_LENGTH];
        int decryptedLength = 0;

        std::string encodedIV = encryptedText.substr(0, EVP_CIPHER_iv_length(cipher));
        std::string encodedData = encryptedText.substr(EVP_CIPHER_iv_length(cipher));

        memcpy(iv, encodedIV.c_str(), encodedIV.length());
        EVP_BytesToKey(cipher, EVP_sha256(), nullptr, reinterpret_cast<const unsigned char*>(password.c_str()), password.length(), 1, key, iv);

        EVP_DecryptInit_ex(ctx, cipher, nullptr, key, iv);
        EVP_DecryptUpdate(ctx, decryptedData, &decryptedLength, reinterpret_cast<const unsigned char*>(encodedData.c_str()), encodedData.length());
        int finalDecryptedLength = 0;
        EVP_DecryptFinal_ex(ctx, decryptedData + decryptedLength, &finalDecryptedLength);
        decryptedLength += finalDecryptedLength;

        EVP_CIPHER_CTX_cleanup(ctx);
        EVP_CIPHER_CTX_free(ctx);

        std::string decryptedString(reinterpret_cast<char*>(decryptedData), decryptedLength);

        return decryptedString;
    }
};

int main() {
    std::string filePath = "passwords.txt";
    std::string masterPassword = "myMasterPassword";
    PasswordManager passwordManager(filePath, masterPassword);

    // Сохранение пароля
    passwordManager.SavePassword("example.com", "john.doe", "password123");

    // Получение пароля
    std::string password = passwordManager.GetPassword("example.com");
    std::cout << "Password: " << password << std::endl;

    return 0;
}
