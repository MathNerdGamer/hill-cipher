/*
MIT License

Copyright (c) 2019 Math Nerd

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
        using hill_key = matrix_t::matrix_t<z97>;

        /** \name Hill Cipher message block
         */
        using msg_block = matrix_t::matrix_t<z97>;
    }

    template<>
    hill_cipher::hill_key hill_cipher::hill_key::inverse() const
    {
        auto size = static_cast<std::size_t>( row_count() );

        hill_cipher::hill_key dec_key{ size, size };

        if ( size == 2 )
        {
            // Check if determinant is 0.
            if( mat[0][0] * mat[1][1] == mat[0][1] * mat[1][0] )
            {
                throw std::invalid_argument("The matrix is not invertible.\n");
            }

            // Calculate and hold determinant.
            hill_cipher::z97 det = mat[0][0] * mat[1][1] - mat[0][1] * mat[1][0];

            // This gives the inverse matrix for 2x2 matrices.
            dec_key[0][0] =  mat[1][1] / det;
            dec_key[0][1] = -mat[0][1] / det;
            dec_key[1][0] = -mat[1][0] / det;
            dec_key[1][1] =  mat[0][0] / det;
        }
        else
        {
            auto key{ *this };
            // Creating identity matrix.
            // dec_key acts as the augmented portion of the key matrix in the Gauss-Jordan Elimination algorithm.
            for( auto i = std::size_t{ 0 }; i < size; ++i )
            {
                for( auto j = std::size_t{ 0 }; j < size; ++j )
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

            for( auto i = std::size_t{ 0 }; i < size; ++i )
            {
                auto max_element = key[i][i].value();
                auto max_row = i;
                for( auto k = std::size_t{ i + 1 }; k < size; ++k )
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

                    for( auto j = std::size_t{ 0 }; j < size; ++j )
                    {
                        key[k][j] -= d * key[i][j];
                        dec_key[k][j] -= d * dec_key[i][j];
                    }

                }
            }

            // Turn key matrix into identity matrix using row operations.
            // Copy these same row operations to dec_key to find the inverse matrix.
            for( auto i = size - 1; i >= 0; --i )
            {   // Loop not infinite -- i = 0 breaks, but work needs to be done in that case first.
                if( key[i][i] == 0 )
                {
                    throw std::invalid_argument("The matrix is not invertible.\n");
                }

                for( auto j = std::size_t{ 0 }; j < size; ++j )
                {
                    dec_key[i][j] /= key[i][i];
                }

                key[i][i] = 1;

                if( i != 0 )
                {
                    for( auto row = i - 1; row >= 0; --row )
                    {   // Loop not infinite -- row = 0 breaks, but work needs to be done in that case first.
                        for( auto column = std::size_t{ 0 }; column < size; ++column )
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
            constexpr std::array<char, 97> ch_table =
            {
                'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
                '0','1','2','3','4','5','6','7','8','9',' ','~','-','=','!','@','#','$','%','^','&','*','(',')','_','+',
                '[',']',';','\'',',','.','/','{','}',':','"','<','>','?','`', '\\', '|', '\t', '\n'
            };

            /** \fn constexpr char z97_to_char(z97 num)
                \brief Returns the character assigned to that integer modulo 97.
             */
            char z97_to_char(z97 num)
            {
                return ch_table[static_cast<std::size_t>(num.value())];
            }

            /** \fn constexpr z97 char_to_z97(char c)
                \brief Returns the integer modulo 97 assigned to that character.
             */
            z97 char_to_z97(char c)
            {
                return std::distance(std::begin(ch_table), std::find(std::begin(ch_table), std::end(ch_table), c));
            }

        } // namespace impl_details

        /** \fn std::string encrypt(hill_key key, std::string pt)
            \brief Encrypts plaintext string using the key by breaking the string into blocks the same size as the matrix key and multiplying by the key.
         */
        std::string encrypt(hill_key key, std::string pt)
        {
            std::int64_t size = key.row_count();

            std::vector<msg_block> plain_text_blocks;
            std::vector<msg_block> cipher_text_blocks;

            using namespace impl_details;

            // Pad plaintext to make its length a multiple of size
            while( (pt.length() % size) != 0 )
            {
                pt += ' ';
            }

            // Take each `size` characters as a message block, put in vector of plaintext blocks.
            for( auto i = 0u; i < pt.length(); i += static_cast<unsigned>(size) )
            {
                msg_block tmp{ size, 1 };

                for( auto j = 0; j < size; ++j )
                {
                    tmp[j][0] = char_to_z97(pt[i + j]);
                }

                plain_text_blocks.push_back(tmp);
            }

            // Multiply each block with the key matrix and put in vector of ciphertext blocks.
            for( auto it = plain_text_blocks.begin(); it != plain_text_blocks.end(); ++it )
            {
                cipher_text_blocks.push_back(key * (*it));
            }

            // Create an empty ciphertext string.
            std::string ct{ "" };

            // Convert each ciphertext block into the corresponding characters.
            for( auto it = cipher_text_blocks.begin(); it != cipher_text_blocks.end(); ++it )
            {
                for( auto j = 0; j < size; ++j )
                {
                    ct += z97_to_char((*it)[j][0]);
                }
            }

            // Return the ciphertext string.
            return ct;
        }

        /** \fn std::string decrypt(hill_key key, std::string const &ct)
            \brief Decrypts ciphertext by calling the encrypt function with the inverse matrix.
         */
        std::string decrypt(hill_key key, std::string const &ct)
        {
            return encrypt(key.inverse(), ct);
        }

        bool is_valid_key(hill_key key)
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
    \section gitlab_link GitLab Link
    View the source code at <a href="https://gitlab.com/mathnerd/hill-cipher">GitLab</a>.
 */
