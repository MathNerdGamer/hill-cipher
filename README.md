# Hill Cipher

A header-only basic Hill Cipher implementation modulo 97 (all characters commonly found on a QWERTY keyboard, including a-z, A-Z, 0-9, all symbols, tab, and newline). Since 97 is prime, Z/97 is a field, which is convenient.

Uses my two header-only implementations of [integers modulo N](https://github.com/MathNerdGamer/integers-modulo-n) and [minimal matrix](https://github.com/MathNerdGamer/minimal-matrix).

# Usage
Here's a basic example:
```
#include "hill_cipher.h"
#include <iostream>

using namespace math_nerd::hill_cipher; // For demonstration purposes.

int main()
{
    constexpr std::int64_t key_size = 5;
    hill_key key{ key_size };

    for( auto i = 0; i < key_size; ++i )
    {
        for( auto j = 0; j < key_size; ++j )
        {
            if( i < j )
            {
                key[i][j] = 5*i - 2*j;
            }
            else
            {
                key[i][j] = 3 * i + j;
            }
        }
    }

    std::string pt = "Hello, world!";

    std::string ct = encrypt(key, pt);

    try
    {
        pt = decrypt(key, ct);
    }
    catch( std::invalid_argument const &e )
    {
        std::cout << e.what();
        return EXIT_FAILURE;
    }

    std::cout << "Plaintext: " << pt << '\n';
    std::cout << "Ciphertext: " << ct << '\n';

    return EXIT_SUCCESS;
}

```

Output:
```
Plaintext: Hello, world!
Ciphertext: aVAn1%,Ew-^t-F[
```
