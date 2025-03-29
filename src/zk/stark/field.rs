use std::error::Error;
use std::ops::{Add, Sub, Mul, Div, Neg};
use num_bigint::{BigUint, ToBigUint};
use num_traits::identities::{One, Zero};
use num_traits::ToPrimitive; // Added this import for to_u64
use num_integer::Integer;
use sha3::{Digest, Sha3_256};

/// Prime field modulus: 2^251 + 17*2^192 + 1
/// This is the same prime used in the STARK system for Ethereum
pub const FIELD_MODULUS: &str = "800000000000011000000000000000000000000000000000000000000000001";

/// A finite field element implementation suitable for zero-knowledge proofs.
/// Implements operations in the finite field F_p where p is FIELD_MODULUS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement {
    /// Internal value representation (0 to FIELD_MODULUS-1)
    value: [u64; 4],
}

impl FieldElement {
    /// Create a new field element from a 4-element u64 array
    pub fn new(value: [u64; 4]) -> Result<Self, Box<dyn Error>> {
        let fe = Self { value };
        if !fe.is_valid() {
            return Err("Value exceeds field modulus".into());
        }
        Ok(fe)
    }
    
    /// Create a field element from a u64 value
    pub fn from_u64(value: u64) -> Self {
        Self {
            value: [value, 0, 0, 0]
        }
    }
    
    /// Create a field element from a byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        if bytes.len() < 32 {
            return Err("Byte array too short for field element".into());
        }
        
        let mut value = [0u64; 4];
        
        // Convert bytes to u64 values, little-endian
        for i in 0..4 {
            let start = i * 8;
            let end = start + 8;
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&bytes[start..end]);
            value[i] = u64::from_le_bytes(chunk);
        }
        
        Self::new(value)
    }
    
    /// Create a field element from a hexadecimal string
    pub fn from_hex(hex: &str) -> Result<Self, Box<dyn Error>> {
        let hex_clean = hex.trim_start_matches("0x");
        let bytes = hex::decode(hex_clean)?;
        
        let biguint = BigUint::from_bytes_be(&bytes);
        Self::from_biguint(&biguint)
    }
    
    /// Create a field element from a BigUint
    pub fn from_biguint(value: &BigUint) -> Result<Self, Box<dyn Error>> {
        // Get the modulus as BigUint
        let modulus = BigUint::parse_bytes(FIELD_MODULUS.as_bytes(), 16)
            .ok_or("Failed to parse field modulus")?;
        
        // Perform modular reduction
        let reduced = value % &modulus;
        
        // Convert to bytes and then to our internal representation
        let bytes = reduced.to_bytes_le();
        let mut value = [0u64; 4];
        
        for (i, chunk) in bytes.chunks(8).enumerate() {
            if i >= 4 {
                break;
            }
            
            let mut padded = [0u8; 8];
            for (j, &byte) in chunk.iter().enumerate() {
                padded[j] = byte;
            }
            
            value[i] = u64::from_le_bytes(padded);
        }
        
        Ok(Self { value })
    }
    
    /// Convert to a byte array (32 bytes, little-endian)
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        
        for i in 0..4 {
            let chunk = self.value[i].to_le_bytes();
            let start = i * 8;
            let end = start + 8;
            bytes[start..end].copy_from_slice(&chunk);
        }
        
        bytes
    }
    
    /// Convert to a hexadecimal string
    pub fn to_hex(&self) -> String {
        let biguint = self.to_biguint();
        format!("{:x}", biguint)
    }
    
    /// Convert to a decimal string
    pub fn to_string(&self) -> String {
        let biguint = self.to_biguint();
        format!("{}", biguint)
    }
    
    /// Convert to a BigUint
    pub fn to_biguint(&self) -> BigUint {
        let mut bytes = Vec::with_capacity(32);
        
        for &val in &self.value {
            bytes.extend_from_slice(&val.to_le_bytes());
        }
        
        BigUint::from_bytes_le(&bytes)
    }
    
    /// Add two field elements
    pub fn add(&self, other: &Self) -> Self {
        let biguint1 = self.to_biguint();
        let biguint2 = other.to_biguint();
        
        let modulus = BigUint::parse_bytes(FIELD_MODULUS.as_bytes(), 16).unwrap();
        let result = (biguint1 + biguint2) % &modulus;
        
        Self::from_biguint(&result).unwrap()
    }
    
    /// Subtract one field element from another
    pub fn sub(&self, other: &Self) -> Self {
        let biguint1 = self.to_biguint();
        let biguint2 = other.to_biguint();
        
        let modulus = BigUint::parse_bytes(FIELD_MODULUS.as_bytes(), 16).unwrap();
        
        let result = if biguint1 >= biguint2 {
            biguint1 - biguint2
        } else {
            &modulus - (biguint2 - biguint1)
        } % &modulus;
        
        Self::from_biguint(&result).unwrap()
    }
    
    /// Multiply two field elements
    pub fn mul(&self, other: &Self) -> Self {
        let biguint1 = self.to_biguint();
        let biguint2 = other.to_biguint();
        
        let modulus = BigUint::parse_bytes(FIELD_MODULUS.as_bytes(), 16).unwrap();
        let result = (biguint1 * biguint2) % &modulus;
        
        Self::from_biguint(&result).unwrap()
    }
    
    /// Compute the multiplicative inverse of a field element
    pub fn inverse(&self) -> Result<Self, Box<dyn Error>> {
        if self.is_zero() {
            return Err("Cannot invert zero".into());
        }
        
        let biguint = self.to_biguint();
        let modulus = BigUint::parse_bytes(FIELD_MODULUS.as_bytes(), 16).unwrap();
        
        // Use Extended Euclidean Algorithm to find modular inverse
        let (gcd, inverse, t) = extended_gcd(&biguint, &modulus);
        
        if !gcd.is_one() {
            return Err("No modular inverse exists".into());
        }
        
        let inverse_biguint = (inverse % &modulus + &modulus) % &modulus;
        Self::from_biguint(&inverse_biguint)
    }
    
    /// Divide one field element by another
    pub fn div(&self, other: &Self) -> Result<Self, Box<dyn Error>> {
        let inverse = other.inverse()?;
        Ok(self.mul(&inverse))
    }
    
    /// Safe division that panics on error - use for operator implementations
    pub fn safe_div(&self, other: &Self) -> Self {
        match self.div(other) {
            Ok(result) => result,
            Err(_) => panic!("Division error (likely division by zero)"),
        }
    }
    
    /// Negate a field element
    pub fn neg(&self) -> Self {
        if self.is_zero() {
            return *self;
        }
        
        let modulus = BigUint::parse_bytes(FIELD_MODULUS.as_bytes(), 16).unwrap();
        let biguint = self.to_biguint();
        let result = &modulus - biguint;
        
        Self::from_biguint(&result).unwrap()
    }
    
    /// Raise to a power (exponentiation)
    pub fn pow(&self, exp: &BigUint) -> Self {
        let biguint = self.to_biguint();
        let modulus = BigUint::parse_bytes(FIELD_MODULUS.as_bytes(), 16).unwrap();
        
        let result = biguint.modpow(exp, &modulus);
        Self::from_biguint(&result).unwrap()
    }
    
    /// Check if this element is zero
    pub fn is_zero(&self) -> bool {
        self.value == [0, 0, 0, 0]
    }
    
    /// Check if this element is one
    pub fn is_one(&self) -> bool {
        self.value == [1, 0, 0, 0]
    }
    
    /// Get the zero element
    pub fn zero() -> Self {
        Self { value: [0, 0, 0, 0] }
    }
    
    /// Get the one element
    pub fn one() -> Self {
        Self { value: [1, 0, 0, 0] }
    }
    
    /// Check if the value is valid (< FIELD_MODULUS)
    fn is_valid(&self) -> bool {
        let modulus = BigUint::parse_bytes(FIELD_MODULUS.as_bytes(), 16).unwrap();
        self.to_biguint() < modulus
    }
    
    /// Generate a random field element
    pub fn random() -> Self {
        use rand::{Rng, thread_rng};
        
        let mut rng = thread_rng();
        let mut value = [0u64; 4];
        
        for i in 0..4 {
            value[i] = rng.gen();
        }
        
        // Ensure it's valid by performing modular reduction
        let biguint = BigUint::from_bytes_le(&value
            .iter()
            .flat_map(|&v| v.to_le_bytes().to_vec())
            .collect::<Vec<u8>>());
            
        let modulus = BigUint::parse_bytes(FIELD_MODULUS.as_bytes(), 16).unwrap();
        let reduced = biguint % modulus;
        
        Self::from_biguint(&reduced).unwrap()
    }
    
    /// Evaluate a polynomial at this field element
    pub fn eval_poly(&self, coefficients: &[Self]) -> Self {
        if coefficients.is_empty() {
            return Self::zero();
        }
        
        // Horner's method for polynomial evaluation
        let mut result = coefficients[coefficients.len() - 1];
        for i in (0..coefficients.len() - 1).rev() {
            result = result.mul(self);
            result = result.add(&coefficients[i]);
        }
        
        result
    }
    
    /// Compute a hash of this field element
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(self.to_bytes());
        let result = hasher.finalize();
        
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

// Implement standard operators for FieldElement
impl Add for FieldElement {
    type Output = Self;
    
    fn add(self, other: Self) -> Self {
        self.add(&other)
    }
}

impl Add<&FieldElement> for FieldElement {
    type Output = Self;
    
    fn add(self, other: &Self) -> Self {
        self.add(other)
    }
}

impl Sub for FieldElement {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self {
        self.sub(&other)
    }
}

impl Sub<&FieldElement> for FieldElement {
    type Output = Self;
    
    fn sub(self, other: &Self) -> Self {
        self.sub(other)
    }
}

impl Mul for FieldElement {
    type Output = Self;
    
    fn mul(self, other: Self) -> Self {
        self.mul(&other)
    }
}

impl Mul<&FieldElement> for FieldElement {
    type Output = Self;
    
    fn mul(self, other: &Self) -> Self {
        self.mul(other)
    }
}

impl Div for FieldElement {
    type Output = Self;
    
    fn div(self, other: Self) -> Self {
        self.safe_div(&other)
    }
}

impl Div<&FieldElement> for FieldElement {
    type Output = Self;
    
    fn div(self, other: &Self) -> Self {
        self.safe_div(other)
    }
}

impl Neg for FieldElement {
    type Output = Self;
    
    fn neg(self) -> Self {
        self.neg()
    }
}

// Extended Euclidean Algorithm to find modular inverse
fn extended_gcd(a: &BigUint, b: &BigUint) -> (BigUint, BigUint, BigUint) {
    if b.is_zero() {
        return (a.clone(), BigUint::from(1u32), BigUint::from(0u32));
    }
    
    let (d, s1, t1) = extended_gcd(b, &(a % b));
    let q = a.div_floor(b);
    let t = s1 - q * &t1;
    
    (d, t1, t)
}

/// Implementation of a polynomial over a finite field
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Polynomial {
    /// Coefficients from lowest to highest degree
    coefficients: Vec<FieldElement>,
}

impl Polynomial {
    /// Create a new polynomial from coefficients
    pub fn new(coeffs: Vec<FieldElement>) -> Self {
        let mut result = Self {
            coefficients: coeffs,
        };
        result.normalize();
        result
    }
    
    /// Create a constant polynomial
    pub fn constant(c: FieldElement) -> Self {
        Self {
            coefficients: vec![c],
        }
    }
    
    /// Create the zero polynomial
    pub fn zero() -> Self {
        Self {
            coefficients: vec![FieldElement::zero()],
        }
    }
    
    /// Create the polynomial x^n
    pub fn monomial(degree: usize) -> Self {
        let mut coeffs = vec![FieldElement::zero(); degree + 1];
        coeffs[degree] = FieldElement::one();
        Self {
            coefficients: coeffs,
        }
    }
    
    /// Get the degree of the polynomial
    pub fn degree(&self) -> usize {
        self.coefficients.len() - 1
    }
    
    /// Normalize by removing trailing zeros
    fn normalize(&mut self) {
        while self.coefficients.len() > 1 && self.coefficients.last().unwrap().is_zero() {
            self.coefficients.pop();
        }
    }
    
    /// Get the coefficients
    pub fn coefficients(&self) -> &[FieldElement] {
        &self.coefficients
    }
    
    /// Evaluate the polynomial at a point
    pub fn evaluate(&self, x: &FieldElement) -> FieldElement {
        x.eval_poly(&self.coefficients)
    }
    
    /// Evaluate the polynomial at multiple points
    pub fn batch_evaluate(&self, points: &[FieldElement]) -> Vec<FieldElement> {
        points.iter().map(|x| self.evaluate(x)).collect()
    }
    
    /// Add two polynomials
    pub fn add(&self, other: &Self) -> Self {
        let max_len = std::cmp::max(self.coefficients.len(), other.coefficients.len());
        let mut result = vec![FieldElement::zero(); max_len];
        
        for (i, coeff) in self.coefficients.iter().enumerate() {
            result[i] = *coeff;
        }
        
        for (i, coeff) in other.coefficients.iter().enumerate() {
            result[i] = result[i].add(coeff);
        }
        
        Self::new(result)
    }
    
    /// Subtract one polynomial from another
    pub fn sub(&self, other: &Self) -> Self {
        let max_len = std::cmp::max(self.coefficients.len(), other.coefficients.len());
        let mut result = vec![FieldElement::zero(); max_len];
        
        for (i, coeff) in self.coefficients.iter().enumerate() {
            result[i] = *coeff;
        }
        
        for (i, coeff) in other.coefficients.iter().enumerate() {
            result[i] = result[i].sub(coeff);
        }
        
        Self::new(result)
    }
    
    /// Multiply two polynomials
    pub fn mul(&self, other: &Self) -> Self {
        let deg_a = self.coefficients.len();
        let deg_b = other.coefficients.len();
        let deg_result = deg_a + deg_b - 1;
        let mut result = vec![FieldElement::zero(); deg_result];
        
        for (i, a) in self.coefficients.iter().enumerate() {
            for (j, b) in other.coefficients.iter().enumerate() {
                let idx = i + j;
                result[idx] = result[idx].add(&a.mul(b));
            }
        }
        
        Self::new(result)
    }
    
    /// Divide a polynomial by another, returning quotient and remainder
    pub fn div_rem(&self, divisor: &Self) -> Result<(Self, Self), Box<dyn Error>> {
        if divisor.coefficients.len() <= 1 && divisor.coefficients[0].is_zero() {
            return Err("Division by zero polynomial".into());
        }
        
        let mut remainder = self.clone();
        let divisor_deg = divisor.degree();
        let leading_coeff = divisor.coefficients[divisor_deg];
        
        let mut quotient_coeffs = vec![
            FieldElement::zero();
            self.coefficients.len().saturating_sub(divisor.coefficients.len()) + 1
        ];
        
        while remainder.degree() >= divisor_deg {
            // Calculate the degree of the term to add to the quotient
            let term_deg = remainder.degree() - divisor_deg;
            
            // Calculate the coefficient of this term
            // Handle division properly without using ?
            let term_coeff = match remainder.coefficients[remainder.degree()].div(&leading_coeff) {
                Ok(coeff) => coeff,
                Err(_) => return Err("Division error".into()),
            };
            
            quotient_coeffs[term_deg] = term_coeff;
            
            // Subtract term * divisor from remainder
            for i in 0..=divisor_deg {
                let idx = term_deg + i;
                let subtraction = term_coeff.mul(&divisor.coefficients[i]);
                if idx < remainder.coefficients.len() {
                    remainder.coefficients[idx] = remainder.coefficients[idx].sub(&subtraction);
                }
            }
            
            remainder.normalize();
        }
        
        Ok((Self::new(quotient_coeffs), remainder))
    }
    
    /// Interpolate a polynomial from points
    pub fn interpolate(points: &[(FieldElement, FieldElement)]) -> Result<Self, Box<dyn Error>> {
        if points.is_empty() {
            return Ok(Self::zero());
        }
        
        // Lagrange interpolation
        let mut result = Self::zero();
        for (i, &(x_i, y_i)) in points.iter().enumerate() {
            let mut term = Self::constant(y_i);
            for (j, &(x_j, _)) in points.iter().enumerate() {
                if i == j {
                    continue;
                }
                
                // Calculate (x - x_j) / (x_i - x_j)
                let numerator = Self::monomial(1).sub(&Self::constant(x_j)); // x - x_j
                let denominator = x_i.sub(&x_j); // x_i - x_j
                let inv_denominator = match denominator.inverse() {
                    Ok(inv) => inv,
                    Err(e) => return Err(e),
                };
                
                // Multiply numerator by 1/denominator
                let mut scaled_numerator = numerator.clone();
                for coeff in &mut scaled_numerator.coefficients {
                    *coeff = coeff.mul(&inv_denominator);
                }
                
                term = term.mul(&scaled_numerator);
            }
            
            result = result.add(&term);
        }
        
        Ok(result)
    }
    
    /// Compute the FFT evaluation of the polynomial at powers of a root of unity
    pub fn fft(&self, omega: &FieldElement, n: usize) -> Vec<FieldElement> {
        if n == 0 || !n.is_power_of_two() {
            panic!("FFT size must be a power of 2");
        }
        
        let mut coeffs = self.coefficients.clone();
        coeffs.resize(n, FieldElement::zero());
        
        // Base case
        if n == 1 {
            return coeffs;
        }
        
        // Divide into even and odd coefficients
        let mut even_coeffs = Vec::with_capacity(n / 2);
        let mut odd_coeffs = Vec::with_capacity(n / 2);
        
        for i in 0..n / 2 {
            even_coeffs.push(coeffs[2 * i]);
            odd_coeffs.push(coeffs[2 * i + 1]);
        }
        
        let even_poly = Polynomial::new(even_coeffs);
        let odd_poly = Polynomial::new(odd_coeffs);
        
        // Compute omega^2
        let omega_squared = omega.mul(omega);
        
        // Recursive FFT on even and odd parts
        let even_vals = even_poly.fft(&omega_squared, n / 2);
        let odd_vals = odd_poly.fft(&omega_squared, n / 2);
        
        // Combine results
        let mut result = Vec::with_capacity(n);
        let mut current_omega = FieldElement::one();
        
        for i in 0..n / 2 {
            let even_val = even_vals[i];
            let odd_val = current_omega.mul(&odd_vals[i]);
            
            result.push(even_val.add(&odd_val));
            result.push(even_val.sub(&odd_val));
            
            current_omega = current_omega.mul(omega);
        }
        
        result
    }
    
    /// Compute the inverse FFT to recover polynomial coefficients
    pub fn ifft(values: &[FieldElement], omega: &FieldElement) -> Self {
        let n = values.len();
        if !n.is_power_of_two() {
            panic!("IFFT size must be a power of 2");
        }
        
        // Compute omega^-1
        let omega_inv = match omega.inverse() {
            Ok(inv) => inv,
            Err(_) => panic!("Failed to compute inverse of omega"),
        };
        
        // Compute FFT with omega^-1
        let mut result = Vec::with_capacity(n);
        let poly = Polynomial::new(values.to_vec());
        let fft_result = poly.fft(&omega_inv, n);
        
        // Scale by 1/n
        let n_biguint = BigUint::from(n as u32);
        let n_field = FieldElement::from_biguint(&n_biguint).unwrap();
        let n_inv = match n_field.inverse() {
            Ok(inv) => inv,
            Err(_) => panic!("Failed to compute inverse of n"),
        };
        
        for val in fft_result {
            result.push(val.mul(&n_inv));
        }
        
        Polynomial::new(result)
    }
    
    /// Multiply two polynomials using FFT
    pub fn mul_fft(&self, other: &Self) -> Self {
        let deg1 = self.degree();
        let deg2 = other.degree();
        let result_deg = deg1 + deg2;
        
        // Find the smallest power of 2 greater than result_deg + 1
        let mut n = 1;
        while n <= result_deg {
            n *= 2;
        }
        n *= 2;  // Double it to prevent circular convolution
        
        // Find a primitive nth root of unity in the field
        // For simplicity, we're assuming one exists for the given n
        // In a real implementation, you'd calculate this based on field properties
        let omega = match Self::find_root_of_unity(n) {
            Ok(root) => root,
            Err(_) => panic!("Could not find a suitable root of unity"),
        };
        
        // Evaluate both polynomials using FFT
        let evals1 = self.fft(&omega, n);
        let evals2 = other.fft(&omega, n);
        
        // Multiply point-wise
        let mut product_evals = Vec::with_capacity(n);
        for i in 0..n {
            product_evals.push(evals1[i].mul(&evals2[i]));
        }
        
        // Recover the product polynomial using inverse FFT
        let mut result = Self::ifft(&product_evals, &omega);
        
        // Truncate to the expected degree
        result.coefficients.truncate(result_deg + 1);
        result.normalize();
        
        result
    }
    
    /// Find a primitive nth root of unity in the field
    fn find_root_of_unity(n: usize) -> Result<FieldElement, Box<dyn Error>> {
        // For demonstration only - in practice, this would be implemented 
        // based on the specific field characteristics
        
        // For our field, we know specific roots of unity exist
        // This is a placeholder - for a real implementation, calculate this properly
        let modulus = BigUint::parse_bytes(FIELD_MODULUS.as_bytes(), 16).unwrap();
        let modulus_minus_one = &modulus - BigUint::from(1u32);
        
        // Find the largest power of 2 dividing p-1
        let mut largest_power_of_two = BigUint::from(1u32);
        let mut max_power = 0;
        
        while (&modulus_minus_one % &(&largest_power_of_two * BigUint::from(2u32))).is_zero() {
            largest_power_of_two *= BigUint::from(2u32);
            max_power += 1;
        }
        
        // Check if we can find a root of unity of the requested order
        if n.next_power_of_two() > 2u32.pow(max_power) as usize {
            return Err(format!("Cannot find a {}th root of unity in this field", n).into());
        }
        
        // Find a quadratic non-residue
        // This is a simplification - in practice, use a known generator
        let gen = FieldElement::from_u64(7);
        
        // Compute the root of unity
        let exp = modulus_minus_one / BigUint::from(n as u32);
        let root = gen.pow(&exp);
        
        // Verify it's a proper root of unity
        let mut check = root;
        for _ in 1..n {
            check = check.mul(&root);
        }
        
        if !check.is_one() {
            return Err("Failed to find a proper root of unity".into());
        }
        
        Ok(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_field_element_basic_operations() -> Result<(), Box<dyn Error>> {
        let a = FieldElement::from_u64(5);
        let b = FieldElement::from_u64(7);
        
        // Addition
        let c = a.add(&b);
        assert_eq!(c.to_biguint().to_u64().unwrap(), 12);
        
        // Subtraction
        let d = b.sub(&a);
        assert_eq!(d.to_biguint().to_u64().unwrap(), 2);
        
        // Multiplication
        let e = a.mul(&b);
        assert_eq!(e.to_biguint().to_u64().unwrap(), 35);
        
        // Inverse and division
        let a_inv = a.inverse()?;
        let a_mul_inv = a.mul(&a_inv);
        assert!(a_mul_inv.is_one(), "a * a^-1 should equal 1");
        
        let f = b.div(&a);
        let g = b.mul(&a_inv);
        assert_eq!(f, g, "Division should match multiplication by inverse");
        
        Ok(())
    }
    
    #[test]
    fn test_polynomial_arithmetic() -> Result<(), Box<dyn Error>> {
        // Create test polynomials: p(x) = 1 + 2x, q(x) = 3 + 4x + 5x^2
        let p = Polynomial::new(vec![
            FieldElement::from_u64(1), 
            FieldElement::from_u64(2)
        ]);
        let q = Polynomial::new(vec![
            FieldElement::from_u64(3), 
            FieldElement::from_u64(4), 
            FieldElement::from_u64(5)
        ]);
        
        // Test addition: p + q = 4 + 6x + 5x^2
        let sum = p.add(&q);
        assert_eq!(sum.coefficients.len(), 3);
        assert_eq!(sum.coefficients[0].to_biguint().to_u64().unwrap(), 4);
        assert_eq!(sum.coefficients[1].to_biguint().to_u64().unwrap(), 6);
        assert_eq!(sum.coefficients[2].to_biguint().to_u64().unwrap(), 5);
        
        // Test multiplication: p * q = 3 + 10x + 13x^2 + 10x^3
        let product = p.mul(&q);
        assert_eq!(product.coefficients.len(), 4);
        assert_eq!(product.coefficients[0].to_biguint().to_u64().unwrap(), 3);
        assert_eq!(product.coefficients[1].to_biguint().to_u64().unwrap(), 10);
        assert_eq!(product.coefficients[2].to_biguint().to_u64().unwrap(), 13);
        assert_eq!(product.coefficients[3].to_biguint().to_u64().unwrap(), 10);
        
        Ok(())
    }
    
    #[test]
    fn test_polynomial_interpolation() -> Result<(), Box<dyn Error>> {
        // Create points for a quadratic polynomial: f(x) = x^2 + 2x + 3
        let points = vec![
            (FieldElement::from_u64(0), FieldElement::from_u64(3)),  // f(0) = 3
            (FieldElement::from_u64(1), FieldElement::from_u64(6)),  // f(1) = 6
            (FieldElement::from_u64(2), FieldElement::from_u64(11)), // f(2) = 11
        ];
        
        // Interpolate the polynomial
        let poly = Polynomial::interpolate(&points)?;
        
        // Check the degree
        assert_eq!(poly.degree(), 2, "Polynomial should have degree 2");
        
        // Check the coefficients
        assert_eq!(poly.coefficients[0].to_biguint().to_u64().unwrap(), 3);
        assert_eq!(poly.coefficients[1].to_biguint().to_u64().unwrap(), 2);
        assert_eq!(poly.coefficients[2].to_biguint().to_u64().unwrap(), 1);
        
        // Evaluate at another point not used for interpolation
        let x = FieldElement::from_u64(3);
        let y = poly.evaluate(&x);
        assert_eq!(y.to_biguint().to_u64().unwrap(), 18); // f(3) = 18
        
        Ok(())
    }
    
    #[test]
    fn test_field_element_serialization() -> Result<(), Box<dyn Error>> {
        // Create a field element
        let a = FieldElement::from_u64(123456789);
        
        // Convert to bytes
        let bytes = a.to_bytes();
        
        // Convert back
        let b = FieldElement::from_bytes(&bytes)?;
        
        // Should be the same
        assert_eq!(a, b);
        
        Ok(())
    }
    
    #[test]
    fn test_field_element_operators() {
        let a = FieldElement::from_u64(5);
        let b = FieldElement::from_u64(7);
        
        // Test + operator
        let c = a + b;
        assert_eq!(c.to_biguint().to_u64().unwrap(), 12);
        
        // Test - operator
        let d = b - a;
        assert_eq!(d.to_biguint().to_u64().unwrap(), 2);
        
        // Test * operator
        let e = a * b;
        assert_eq!(e.to_biguint().to_u64().unwrap(), 35);
        
        // Test / operator
        let f = b / a;
        // For small integers, 7/5 = 1 with remainder 2, but in a field this may be different
        // So we check f * a = b
        let check = f * a;
        assert_eq!(check, b);
        
        // Test negation
        let g = -a;
        let h = g + a;
        assert!(h.is_zero());
    }
}