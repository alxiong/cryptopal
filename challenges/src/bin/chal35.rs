fn main() {
    println!("🔓 Challenge 35");
    // the code would be tedious and repetitive, here's why for some g, DHKE is broken
    println!("* g=1, g^a = 1, regardless of a");
    println!("* g=p, g^a = p^a = 0 mod p, regardless of a");
    println!("* g=p-1, g^a = 1 or p-1 mod p, each value 50% of the time");
    println!("Thus, the first two choices of g makes the shared key completely predictable, and the thrid choice makes it limited 2 possibilities only.");
}
