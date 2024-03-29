#pragma once
#ifndef MATH_NERD_HILL_CIPHER_H
#define MATH_NERD_HILL_CIPHER_H
#include <algorithm>
#include <array>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <math_nerd/int_mod.h>
#include <math_nerd/matrix_t.h>

/** \file hill_cipher.h
    \brief A basic Hill Cipher implementation modulo 97.
 */

 /** \namespace math_nerd
     \brief Namespace for all of my projects.
  */
namespace math_nerd
{
    /** \namespace math_nerd::hill_cipher
        \brief Namespace for the Hill Cipher implementation.
     */
    namespace hill_cipher
    {
        /** \name Integer modulo 97
         */
        using z97 = int_mod::int_mod<97>;

        /** \name Hill Cipher key
         */
        using hill_key  = matrix_t::matrix_t<z97>;
        using msg_block = std::vector<z97>;
    }

    /** \fn auto hill_cipher::hill_key::inverse() const -> hill_cipher::hill_key
        \brief Returns the inverse matrix of the hill ciper key.
     */
    template<>
    auto hill_cipher::hill_key::inverse() const -> hill_cipher::hill_key
    {
        auto size = row_count();

        hill_cipher::hill_key dec_key{ size };

        if( size == 2 )
        {
            // Check if determinant is 0.
            if( mat[0][0] * mat[1][1] == mat[0][1] * mat[1][0] )
            {
                throw std::invalid_argument("The matrix is not invertible.\n");
            }

            // Calculate and hold determinant.
            hill_cipher::z97 det = mat[0][0] * mat[1][1] - mat[0][1] * mat[1][0];

            // This gives the inverse matrix for 2x2 matrices.
            dec_key[0][0] = mat[1][1] / det;
            dec_key[0][1] = -mat[0][1] / det;
            dec_key[1][0] = -mat[1][0] / det;
            dec_key[1][1] = mat[0][0] / det;
        }
        else
        {
            auto key{ *this };
            // Creating identity matrix.
            // dec_key acts as the augmented portion of the key matrix in the Gauss-Jordan Elimination algorithm.
            for( auto i = 0; i < size; ++i )
            {
                for( auto j = 0; j < size; ++j )
                {
                    if( j == i )
                    {
                        dec_key[i][j] = 1;
                    }
                    else
                    {
                        dec_key[i][j] = 0;
                    }
                }
            }

            for( auto i = 0; i < size; ++i )
            {
                auto max_element = key[i][i].value();
                auto max_row = i;
                for( auto k = i + 1; k < size; ++k )
                {
                    if( key[k][i].value() > max_element )
                    {
                        max_element = key[k][i].value();
                        max_row = k;
                    }
                }

                // Swap maximum element in pivot positions to their corresponding rows
                if( i < max_row )
                {
                    for( auto j = 0u; j < size; ++j )
                    {
                        auto tmp = key[max_row][j];
                        key[max_row][j] = key[i][j];
                        key[i][j] = tmp;

                        tmp = dec_key[max_row][j];
                        dec_key[max_row][j] = dec_key[i][j];
                        dec_key[i][j] = tmp;
                    }
                }

                // Make all elements in the rows below the pivot zero using row operations.
                for( auto k = i + 1; k < size; ++k )
                {
                    if( key[i][i] == 0 )
                    {
                        throw std::invalid_argument("The matrix is not invertible.\n");
                    }

                    auto d = key[k][i] / key[i][i];

                    for( auto j = 0; j < size; ++j )
                    {
                        key[k][j] -= d * key[i][j];
                        dec_key[k][j] -= d * dec_key[i][j];
                    }

                }
            }

            // Turn key matrix into identity matrix using row operations.
            // Copy these same row operations to dec_key to find the inverse matrix.
            for( auto i = size - 1; i >= 0; --i )
            {
                if( key[i][i] == 0 )
                {
                    throw std::invalid_argument("The matrix is not invertible.\n");
                }

                for( auto j = 0; j < size; ++j )
                {
                    dec_key[i][j] /= key[i][i];
                }

                key[i][i] = 1;

                if( i != 0 )
                {
                    for( auto row = i - 1; row >= 0; --row )
                    {   // Loop not infinite -- row = 0 breaks, but work needs to be done in that case first.
                        for( auto column = 0; column < size; ++column )
                        {
                            dec_key[row][column] -= dec_key[i][column] * key[row][i];
                        }

                        key[row][i] = 0;

                        if( row == 0 )
                        {
                            break;
                        }
                    }
                }
                else
                {
                    break;
                }
            }
        }

        return dec_key;
    }

    namespace hill_cipher
    {
        /** \namespace math_nerd::hill_cipher::impl_details
            \brief Contains implementation details.
         */
        namespace impl_details
        {
            /** \property ch_table
                \brief The character table.
             */
            constexpr std::array<char, 97> ch_table{
            {
                'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
                '0','1','2','3','4','5','6','7','8','9',' ','~','-','=','!','@','#','$','%','^','&','*','(',')','_','+',
                '[',']',';','\'',',','.','/','{','}',':','"','<','>','?','`', '\\', '|', '\t', '\n'
            } };

            /** \fn constexpr char z97_to_char(z97 num)
                \brief Returns the character assigned to that integer modulo 97.
             */
            constexpr auto z97_to_char(z97 num) -> char
            {
                return ch_table[static_cast<std::size_t>(num.value())];
            }

            /** \fn constexpr z97 char_to_z97(char c)
                \brief Returns the integer modulo 97 assigned to that character.
             */
            constexpr auto char_to_z97(char const c) -> z97
            {
                return std::distance(std::begin(ch_table), std::find(std::begin(ch_table), std::end(ch_table), c));
            }

        } // namespace impl_details

        /** \fn auto encrypt(hill_key key, std::string pt) -> std::string
            \brief Encrypts plaintext string using the key by breaking the string into blocks the same size as the matrix key and multiplying by the key.
         */
        auto encrypt(hill_key key, std::string pt) -> std::string
        {
            std::int64_t size = key.row_count();

            using namespace impl_details;

            // Pad plaintext to make its length a multiple of size
            while( (pt.length() % size) != 0 )
            {
                pt += ' ';
            }

            std::string ct;
            ct.resize(pt.size());

            msg_block block(size);

            // Take each `size` characters as a message block and encrypt.
            for( auto i = 0u, idx = 0u; i < pt.length(); i += static_cast<std::uint32_t>(size), ++idx )
            {
                for( auto j = 0; j < size; ++j )
                {
                    block[j] = char_to_z97(pt[i + j]);
                }

                auto cipher = key * block;

                for( auto j = 0; j < size; ++j )
                {
                    ct[idx * size + j] = z97_to_char(cipher[j][0]);
                }
            }

            return ct;
        }

        /** \fn auto decrypt(hill_key key, std::string const &ct) -> std::string
            \brief Decrypts ciphertext by calling the encrypt function with the inverse matrix.
         */
        auto decrypt(hill_key key, std::string const &ct) -> std::string
        {
            return encrypt(key.inverse(), ct);
        }

        /** \fn auto is_valid_key(hill_key const &key) -> bool
            \brief Determines if a provided key matrix is valid (invertible).
         */
        auto is_valid_key(hill_key const &key) -> bool
        {
            try
            {
                key.inverse();
            }
            catch( std::invalid_argument const & )
            {
                return false;
            }

            return true;
        }

    } // namespace hill_cipher

} // namespace math_nerd
#endif // MATH_NERD_HILL_CIPHER

/** \mainpage Hill Cipher, modulo 97
    \section the_math The Math
    The <a href="https://en.wikipedia.org/wiki/Hill_cipher">Hill Cipher</a> is a classical cryptosystem
    using matrix multiplication and modular arithmetic. Essentially, plaintext is partitioned into blocks
    according to the size of the key matrix, with padding added to the final block as needed. Then, each character
    is assigned a numerical value (typically 0-25 for A-Z) and the blocks are treated as vectors, which are then
    multiplied by the key matrix. The key matrix is required to be invertible, so that plaintext may be retrieved
    from the ciphertext by the same process (with the key matrix replaced by its inverse).

    The classical version is taken modulo 26. However, since 26 is not prime, there is a subtle issue to take into account,
    namely the fact that a matrix is invertible if and only if the determinant, itself, is invertible modulo 26. This means
    that simply testing for 0 (mod 26) determinant is not enough -- one must also check that the determinant is not a factor
    of 26 (2 or 13).

    In this implementation of the Hill Cipher, we use a character set with 97 symbols. Since 97 is prime, we avert the disadvantage
    of the classical version.

    This projects uses two types that I implemented, <a href="../matrix_t/index.html">Minimal Matrix</a> and <a href="../int_mod/index.html">Integers Modulo N</a>.

    \section gitlab_link GitLab Link
    View the source code at <a href="https://gitlab.com/mathnerd/hill-cipher">GitLab</a>.
 */
