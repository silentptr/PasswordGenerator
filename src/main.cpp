#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <memory>

#include <openssl/rand.h>
#include <openssl/evp.h>

class Password
{
private:
    std::unique_ptr<char[]> m_Data;
    std::size_t m_Len;
public:
    Password(std::size_t len) noexcept : m_Len(len)
    {
        m_Data = std::make_unique<char[]>(m_Len + 1);
        m_Data[m_Len] = '\0';
    }

    ~Password() noexcept
    {
        OPENSSL_cleanse(m_Data.get(), m_Len);
    }

    char* Get() const noexcept { return m_Data.get(); }
    std::size_t Length() const noexcept { return m_Len; }
};

void gen_password(Password& passwd)
{
    std::unique_ptr<unsigned char[]> buf = std::make_unique<unsigned char[]>(passwd.Length());
    RAND_bytes(buf.get(), passwd.Length());
    std::unique_ptr<unsigned char[]> output = std::make_unique<unsigned char[]>(passwd.Length() * 4);
    EVP_EncodeBlock(output.get(), buf.get(), passwd.Length());
    std::memcpy(passwd.Get(), output.get(), passwd.Length());
    OPENSSL_cleanse(buf.get(), passwd.Length());
    OPENSSL_cleanse(output.get(), passwd.Length() * 4);
}

int main(int argc, char** argv)
{
    std::cout << "Welcome to password generator v1.3!\n";
    std::cout << "Using OpenSSL " << OpenSSL_version(OPENSSL_VERSION_STRING) << '\n';

    if (RAND_poll() == 0)
    {
        std::cout << "An error occured.\n";
        return EXIT_FAILURE;
    }

    std::size_t length;

    if (argc >= 2)
    {
        try
        {
            length = std::stoull(argv[argc - 1], NULL);
        }
        catch (...)
        {
            length = 0;
        }
    }
    else
    {
        std::cout << "Enter password length: ";
        std::cin >> length;
    }

    if (length < 1 || length > 4096)
    {
        std::cout << "Password length must be 1-4096 characters.\n";
        return EXIT_FAILURE;
    }

    std::cout << "Generating a password of length " << std::to_string(length) << "...\n";
    Password password(length);
    gen_password(password);
    std::cout << "Generated password: " << password.Get() << '\n';
    return 0;
}