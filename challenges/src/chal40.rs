use super::chal39::mod_inv;
use num::BigUint;

// returns the solution x to the
// x = a0 mod n0, x = a1 mod n1, x = a2 mod n2
// functions using CRT in its constructive definition
// returns \Sigma (ai * n_hat_i * ui) where n_hat_i = N / ni, N = n0*n1*n2, ui =
// n_hat_i^-1 mod n_i
pub fn three_moduli_crt(
    a0: &BigUint,
    a1: &BigUint,
    a2: &BigUint,
    n0: &BigUint,
    n1: &BigUint,
    n2: &BigUint,
) -> BigUint {
    let n_hat_0 = n1 * n2;
    let n_hat_1 = n0 * n2;
    let n_hat_2 = n0 * n1;
    let x = a0 * &n_hat_0 * mod_inv(&n_hat_0, &n0).unwrap()
        + a1 * &n_hat_1 * mod_inv(&n_hat_1, &n1).unwrap()
        + a2 * &n_hat_2 * mod_inv(&n_hat_2, &n2).unwrap();
    x % (n0 * n1 * n2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num::FromPrimitive;
    #[test]
    fn test_crt() {
        let a0 = BigUint::from_u64(3).unwrap();
        let a1 = BigUint::from_u64(2).unwrap();
        let a2 = BigUint::from_u64(4).unwrap();
        let n0 = BigUint::from_u64(5).unwrap();
        let n1 = BigUint::from_u64(6).unwrap();
        let n2 = BigUint::from_u64(7).unwrap();

        assert_eq!(
            three_moduli_crt(&a0, &a1, &a2, &n0, &n1, &n2),
            BigUint::from_u64(158).unwrap()
        );
    }
}
