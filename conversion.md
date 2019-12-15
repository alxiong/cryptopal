## Hex String, UTF-8 Collection, Char slice, u8

Firstly, hex string (e.g. `52bc44d5378309ee2abf1539bf71de1b7d7be3b5`):
fundamentally is a **string** of hexadecimal char. The most two common
conversion would be converting to `Vec<char>` and `Vec<u8>`.

```rust
let hex = "52bc44d";
let char_collection: Vec<_> = hex.chars().collect();
let bytes: Vec<u8> = hex.as_bytes(); // to_bytes() if want ownership
// char_collection: ['5', '2', 'b', 'c', '4', '4', 'd']
// bytes: [53, 50, 98, 99, 52, 52, 100]

// reverse conversion:
let hex == String::from_utf8(bytes).unwrap();
```

Remember that a [char](https://doc.rust-lang.org/std/primitive.char.html) is a
_Unicode code scalar_ and when represented in UTF-8 bytes, a single `char` could
takes variable length of `u8`: for ASCII character, one `char` is one byte
(which is why `char_collection` and `bytes` above have the same length); for
characters like "你好", `"你好".as_bytes() == [228, 189, 160, 229, 165, 189]`

To repeat another point brought up in [Rust
book](https://doc.rust-lang.org/book/ch08-02-strings.html#internal-representation),
`String` is implemented as `struct { vec: Vec<u8> }`, and due to the intricate
UTF-8 standard, it's not suggested to access through index.

When attempting to operate (e.g. XOR two hex string) on hex value, always operate on **bytes** (`u8`), not
on `char`. Unless you want to get the actual decimal value:

```rust
assert_eq!('f'.to_digit(16), Some(15));
```
