/*
MIT License

Copyright (c) 2018 Math Nerd

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
        template <std::size_t size>
        using hill_key = matrix_t::matrix_t<z97, size, size>;

        /** \name Hill Cipher message block
         */
        template <std::size_t size>
        using msg_block = matrix_t::matrix_t<z97, size, 1>;

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
            constexpr char z97_to_char(z97 num)
            {
                return ch_table[static_cast<std::size_t>(num.value())];
            }

            /** \fn constexpr z97 char_to_z97(char c)
                \brief Returns the integer modulo 97 assigned to that character.
             */
            constexpr z97 char_to_z97(char c)
            {
                return std::distance(std::begin(ch_table), find(std::begin(ch_table), std::end(ch_table), c));
            }

            /** \fn hill_key<size> inverse_of(hill_key<size> key)
                \brief Returns the inverse of the size x size Hill Cipher key matrix using Gauss-Jordan Elimination for sizes > 2.
                       For size = 2, assuming the determinant \f$ ad-bc\neq 0 \f$, we have
                       \f$\left[\begin{array}{cc} a & b\\ c & d \end{array}\right]^{-1}=\frac{1}{ad-bc}\left[\begin{array}{cc} d & -b\\ -c & a \end{array}\right]\f$
             */
            template <std::size_t size>
            hill_key<size> inverse_of(hill_key<size> key);
        } // namespace impl_details

        /** \fn std::string encrypt(hill_key<size> key, std::string pt)
            \brief Encrypts plaintext string using the key by breaking the string into blocks the same size as the matrix key and multiplying by the key.
         */
        template <std::size_t size>
        std::string encrypt(hill_key<size> key, std::string pt)
        {
            std::vector<msg_block<size>> plain_text_blocks;
            std::vector<msg_block<size>> cipher_text_blocks;

            using namespace impl_details;

            // Pad plaintext to make its length a multiple of size
            while( (pt.length() % size) != 0 )
            {
                pt += ' ';
            }

            // Take each `size` characters as a message block, put in vector of plaintext blocks.
            for( auto i = 0u; i < pt.length(); i += size )
            {
                msg_block<size> tmp;

                for( auto j = 0u; j < size; ++j )
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
                for( auto j = 0u; j < size; ++j )
                {
                    ct += z97_to_char((*it)[j][0]);
                }
            }

            // Return the ciphertext string.
            return ct;
        }

        /** \fn std::string decrypt(hill_key<size> key, std::string const &ct)
            \brief Decrypts ciphertext by calling the encrypt function with the inverse matrix.
         */
        template <std::size_t size>
        std::string decrypt(hill_key<size> key, std::string const &ct)
        {
            return encrypt(impl_details::inverse_of(key), ct);
        }

        template <std::size_t size>
        hill_key<size> impl_details::inverse_of(hill_key<size> key)
        {

            hill_key<size> dec_key;
    
            if constexpr ( size == 2 )
            {
                // Check if determinant is 0.
                if( key[0][0] * key[1][1] == key[0][1] * key[1][0] )
                {
                    throw std::invalid_argument("The matrix is not invertible.\n");
                }

                // Calculate and hold determinant.
                z97 det = key[0][0] * key[1][1] - key[0][1] * key[1][0];

                // This gives the inverse matrix for 2x2 matrices.
                dec_key[0][0] =  key[1][1] / det;
                dec_key[0][1] = -key[0][1] / det;
                dec_key[1][0] = -key[1][0] / det;
                dec_key[1][1] =  key[0][0] / det;

                return dec_key;
            }
            else
            {
                // Creating identity matrix.
                // dec_key acts as the augmented portion of the key matrix in the Gauss-Jordan Elimination algorithm.
                for( auto i = 0u; i < size; ++i )
                {
                    for( auto j = 0u; j < size; ++j )
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

                for( auto i = 0u; i < size; ++i )
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
                        {
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

                return dec_key;
            }
        }

    } // namespace hill_cipher
} // namespace math_nerd
#endif

/** \mainpage Hill Cipher, modulo 97
    \section gitlab_link GitLab Link
    View the source code at <a href="https://gitlab.com/mathnerd/hill-cipher">GitLab</a>.
 */
