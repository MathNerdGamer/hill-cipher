#include <math_nerd/hill_cipher.h>

#define CATCH_DEFINE_MAIN
#include "catch.hpp"

namespace hc = math_nerd::hill_cipher;

TEST_CASE("Testing Matrix Key Inverse")
{
    SECTION("Testing 2x2 Case")
    {
        constexpr std::int64_t key_size = 2;

        hc::hill_key key{ key_size };
        hc::hill_key identity{ key_size };

        for( auto i{ 0u }; i < key_size; ++i )
        {
            for( auto j{ 0u }; j < key_size; ++j )
            {
                if( i < j )
                {
                    key[i][j] = 2ULL * i - 3ULL * j;
                }
                else
                {
                    key[i][j] = 5ULL * i + j;
                }

                if( i == j )
                {
                    identity[i][j] = 1;
                }
                else
                {
                    identity[i][j] = 0;
                }
            }
        }

        auto key_inverse{ key.inverse() };

        REQUIRE(key * key_inverse == identity);
    }

    SECTION("Testing N x N Case")
    {
        constexpr std::int64_t key_size = 5;

        hc::hill_key key{ key_size };
        hc::hill_key identity{ key_size };

        for( auto i{ 0u }; i < key_size; ++i )
        {
            for( auto j{ 0u }; j < key_size; ++j )
            {
                if( i < j )
                {
                    key[i][j] = 5ULL * i - 2ULL * j;
                }
                else
                {
                    key[i][j] = 3ULL * i + j;
                }

                if( i == j )
                {
                    identity[i][j] = 1;
                }
                else
                {
                    identity[i][j] = 0;
                }
            }
        }

        auto key_inverse{ key.inverse() };

        REQUIRE(key * key_inverse == identity);
    }
}

TEST_CASE("Testing Character Table")
{
    SECTION("z97 -> char")
    {
        hc::z97 num{ 17 };

        REQUIRE(hc::impl_details::z97_to_char(num) == 'R');
    }

    SECTION("char -> z97")
    {
        hc::z97 num{ hc::impl_details::char_to_z97('T') };
        REQUIRE(num == 19);
    }
}

TEST_CASE("Testing Encryption and Decryption")
{
    SECTION("Encryption; 2 x 2 Case")
    {
        constexpr std::int64_t key_size = 2;

        hc::hill_key key{ key_size };
        hc::hill_key identity{ key_size };

        for( auto i{ 0u }; i < key_size; ++i )
        {
            for( auto j{ 0u }; j < key_size; ++j )
            {
                if( i < j )
                {
                    key[i][j] = 2ULL * i - 3ULL * j;
                }
                else
                {
                    key[i][j] = 5ULL * i + j;
                }
            }
        }

        std::string pt = "Hill Cipher!";

        REQUIRE(hc::encrypt(key, pt) == "`t.T?f^cH2\\d");
    }

    SECTION("Decryption; 2 x 2 Case")
    {
        constexpr std::int64_t key_size = 2;

        hc::hill_key key{ key_size };
        hc::hill_key identity{ key_size };

        for( auto i{ 0u }; i < key_size; ++i )
        {
            for( auto j{ 0u }; j < key_size; ++j )
            {
                if( i < j )
                {
                    key[i][j] = 2ULL * i - 3ULL * j;
                }
                else
                {
                    key[i][j] = 5ULL * i + j;
                }
            }
        }

        std::string ct = "Cipher text!";

        REQUIRE(hc::decrypt(key, ct) == "b-Xzo:`s;:%,");
    }

    SECTION("Encryption; N x N Case")
    {
        constexpr std::int64_t key_size = 5;
        hc::hill_key key{ key_size };

        for( auto i{ 0u }; i < key_size; ++i )
        {
            for( auto j{ 0u }; j < key_size; ++j )
            {
                if( i < j )
                {
                    key[i][j] = 5ULL * i - 2 * j;
                }
                else
                {
                    key[i][j] = 3ULL * i + j;
                }
            }
        }

        std::string pt = "Hello, world!";

        REQUIRE(hc::encrypt(key, pt) == "aVAn1%,Ew-^t-F[");
    }

    SECTION("Decryption; N x N Case")
    {
        constexpr std::int64_t key_size = 5;
        hc::hill_key key{ key_size };

        for( auto i{ 0u }; i < key_size; ++i )
        {
            for( auto j{ 0u }; j < key_size; ++j )
            {
                if( i < j )
                {
                    key[i][j] = 5ULL * i - 2 * j;
                }
                else
                {
                    key[i][j] = 3ULL * i + j;
                }
            }
        }

        std::string ct = "This here be some cipher text!";

        REQUIRE(hc::decrypt(key, ct) == "R\tn3\trWpu\\\tFWt/}1zuTz\nBnayk^:S");
    }
}
