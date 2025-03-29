//! Polynomial implementation for STARK proofs
use crate::zk::stark::field::FieldElement;
use std::ops::{Add, Div, Mul, Neg, Sub};

/// Polynomial with coefficients in a finite field
#[derive(Debug, Clone, PartialEq)]
pub struct Polynomial {
    /// Coefficients, from lowest to highest degree
    pub coefficients: Vec<FieldElement>,
}

impl Polynomial {
    /// Create a new polynomial from coefficients
    pub fn new(coefficients: Vec<FieldElement>) -> Self {
        let mut result = Self { coefficients };
        result.trim();
        result
    }

    /// Create a zero polynomial
    pub fn zero() -> Self {
        Self { coefficients: vec![FieldElement::zero()] }
    }

    /// Create a constant polynomial
    pub fn constant(c: FieldElement) -> Self {
        Self { coefficients: vec![c] }
    }

    /// Create the monomial x^degree
    pub fn monomial(degree: usize) -> Self {
        let mut coefficients = vec![FieldElement::zero(); degree + 1];
        coefficients[degree] = FieldElement::one();
        Self { coefficients }
    }

    /// Trim leading zeros from the polynomial
    fn trim(&mut self) {
        while self.coefficients.len() > 1 && self.coefficients.last().unwrap() == &FieldElement::zero() {
            self.coefficients.pop();
        }
    }

    /// Get the degree of the polynomial
    pub fn degree(&self) -> usize {
        self.coefficients.len() - 1
    }

    /// Evaluate the polynomial at a given point
    pub fn evaluate(&self, x: FieldElement) -> FieldElement {
        // Horner's method for efficient evaluation
        let mut result = FieldElement::zero();
        for &coeff in self.coefficients.iter().rev() {
            result = result * x + coeff;
        }
        result
    }

    /// Interpolate a polynomial from points
    /// Uses Lagrange interpolation
    pub fn interpolate(points: &[(FieldElement, FieldElement)]) -> Self {
        let n = points.len();
        
        if n == 0 {
            return Polynomial::zero();
        }
        
        // Build the Lagrange basis polynomials
        let mut result = Polynomial::zero();
        
        for i in 0..n {
            let (xi, yi) = points[i];
            let mut basis = Polynomial::constant(FieldElement::one());
            
            for j in 0..n {
                if i == j { continue; }
                let (xj, _) = points[j];
                
                // Compute (x - xj) / (xi - xj)
                let mut term = Polynomial::new(vec![
                    -xj,  // Constant term: -xj
                    FieldElement::one(), // Coefficient of x: 1
                ]);
                
                let denom = xi - xj;
                let denom_inv = denom.inverse()
                    .expect("Points must be distinct for interpolation");
                
                for c in &mut term.coefficients {
                    *c = *c * denom_inv;
                }
                
                basis = basis * term;
            }
            
            // Multiply by yi and add to result
            for c in &mut basis.coefficients {
                *c = *c * yi;
            }
            
            result = result + basis;
        }
        
        result
    }
    
    /// Fast Fourier Transform (FFT) for polynomial evaluation at powers of a root of unity
    /// This is a naive implementation for demonstration
    pub fn fft(&self, omega: FieldElement, n: usize) -> Vec<FieldElement> {
        let mut result = vec![FieldElement::zero(); n];
        
        for i in 0..n {
            let x = omega.pow(i as u64);
            result[i] = self.evaluate(x);
        }
        
        result
    }
    
    /// Inverse FFT for polynomial interpolation from evaluations at powers of a root of unity
    pub fn ifft(values: &[FieldElement], omega: FieldElement) -> Self {
        let n = values.len();
        
        // Build points (ω^i, value_i)
        let mut points = Vec::with_capacity(n);
        for i in 0..n {
            points.push((omega.pow(i as u64), values[i]));
        }
        
        Self::interpolate(&points)
    }
}

// Arithmetic operations for polynomials
impl Add for Polynomial {
    type Output = Self;
    
    fn add(self, rhs: Self) -> Self {
        let max_len = std::cmp::max(self.coefficients.len(), rhs.coefficients.len());
        let mut result = vec![FieldElement::zero(); max_len];
        
        for (i, &c) in self.coefficients.iter().enumerate() {
            result[i] = c;
        }
        
        for (i, &c) in rhs.coefficients.iter().enumerate() {
            result[i] = result[i] + c;
        }
        
        Polynomial::new(result)
    }
}

impl Sub for Polynomial {
    type Output = Self;
    
    fn sub(self, rhs: Self) -> Self {
        let max_len = std::cmp::max(self.coefficients.len(), rhs.coefficients.len());
        let mut result = vec![FieldElement::zero(); max_len];
        
        for (i, &c) in self.coefficients.iter().enumerate() {
            result[i] = c;
        }
        
        for (i, &c) in rhs.coefficients.iter().enumerate() {
            result[i] = result[i] - c;
        }
        
        Polynomial::new(result)
    }
}

impl Mul for Polynomial {
    type Output = Self;
    
    fn mul(self, rhs: Self) -> Self {
        let a_deg = self.coefficients.len();
        let b_deg = rhs.coefficients.len();
        let result_deg = a_deg + b_deg - 1;
        
        let mut result = vec![FieldElement::zero(); result_deg];
        
        for i in 0..a_deg {
            for j in 0..b_deg {
                result[i + j] = result[i + j] + self.coefficients[i] * rhs.coefficients[j];
            }
        }
        
        Polynomial::new(result)
    }
}

impl Neg for Polynomial {
    type Output = Self;
    
    fn neg(self) -> Self {
        let mut result = self.clone();
        for c in &mut result.coefficients {
            *c = -*c;
        }
        result
    }
}

impl Div for Polynomial {
    type Output = (Self, Self); // Returns (quotient, remainder)
    
    fn div(self, rhs: Self) -> Self::Output {
        if rhs.coefficients.len() == 1 && rhs.coefficients[0] == FieldElement::zero() {
            panic!("Division by zero polynomial");
        }
        
        let mut remainder = self.clone();
        let divisor_degree = rhs.degree();
        let divisor_leading_coeff = rhs.coefficients[divisor_degree];
        let divisor_leading_inv = divisor_leading_coeff.inverse()
            .expect("Leading coefficient must be invertible");
        
        let mut quotient_coeffs = vec![FieldElement::zero(); remainder.degree() + 1];
        
        while remainder.degree() >= divisor_degree && !remainder.coefficients.is_empty() {
            let remainder_degree = remainder.degree();
            let term_degree = remainder_degree - divisor_degree;
            
            let term_coeff = remainder.coefficients[remainder_degree] * divisor_leading_inv;
            quotient_coeffs[term_degree] = term_coeff;
            
            // Subtract term * divisor from remainder
            for i in 0..=divisor_degree {
                let idx = term_degree + i;
                if idx < remainder.coefficients.len() {
                    remainder.coefficients[idx] = remainder.coefficients[idx] - term_coeff * rhs.coefficients[i];
                }
            }
            
            remainder.trim();
        }
        
        (Polynomial::new(quotient_coeffs), remainder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_basics() {
        // Create P(x) = 1 + 2x + 3x^2
        let p = Polynomial::new(vec![
            FieldElement::new(1),
            FieldElement::new(2),
            FieldElement::new(3)
        ]);
        
        // Check degree
        assert_eq!(p.degree(), 2);
        
        // Evaluate at x = 2 should be 1 + 2*2 + 3*2^2 = 1 + 4 + 12 = 17
        let result = p.evaluate(FieldElement::new(2));
        assert_eq!(result.0, 17);
    }

    #[test]
    fn test_polynomial_arithmetic() {
        // P(x) = 1 + 2x
        let p = Polynomial::new(vec![
            FieldElement::new(1),
            FieldElement::new(2)
        ]);
        
        // Q(x) = 3 + 4x + 5x^2
        let q = Polynomial::new(vec![
            FieldElement::new(3),
            FieldElement::new(4),
            FieldElement::new(5)
        ]);
        
        // P + Q = 4 + 6x + 5x^2
        let sum = p.clone() + q.clone();
        assert_eq!(sum.coefficients, vec![
            FieldElement::new(4),
            FieldElement::new(6),
            FieldElement::new(5)
        ]);
        
        // P * Q = 3 + 10x + 13x^2 + 10x^3
        let product = p * q;
        assert_eq!(product.coefficients, vec![
            FieldElement::new(3),
            FieldElement::new(10),
            FieldElement::new(13),
            FieldElement::new(10)
        ]);
    }

    #[test]
    fn test_polynomial_interpolation() {
        // Create points for f(x) = x^2
        let points = vec![
            (FieldElement::new(0), FieldElement::new(0)),  // f(0) = 0
            (FieldElement::new(1), FieldElement::new(1)),  // f(1) = 1
            (FieldElement::new(2), FieldElement::new(4)),  // f(2) = 4
        ];
        
        let poly = Polynomial::interpolate(&points);
        
        // The result should be a degree 2 polynomial
        assert_eq!(poly.degree(), 2);
        
        // Check that it evaluates correctly at the interpolation points
        for (x, y) in points {
            assert_eq!(poly.evaluate(x), y);
        }
        
        // Check at another point: f(3) = 9
        assert_eq!(poly.evaluate(FieldElement::new(3)).0, 9);
    }

    #[test]
    fn test_polynomial_division() {
        // P(x) = x^3 + 2x^2 + 3x + 4
        let p = Polynomial::new(vec![
            FieldElement::new(4),
            FieldElement::new(3),
            FieldElement::new(2),
            FieldElement::new(1)
        ]);
        
        // Q(x) = x + 1
        let q = Polynomial::new(vec![
            FieldElement::new(1),
            FieldElement::new(1)
        ]);
        
        // Divide P by Q
        let (quotient, remainder) = p / q;
        
        // Quotient should be x^2 + x + 2
        assert_eq!(quotient.coefficients, vec![
            FieldElement::new(2),
            FieldElement::new(1),
            FieldElement::new(1)
        ]);
        
        // Remainder should be 2
        assert_eq!(remainder.coefficients, vec![
            FieldElement::new(2)
        ]);
        
        // Verify: P = Q * quotient + remainder
        let reconstructed = q * quotient + remainder;
        assert_eq!(reconstructed.coefficients, vec![
            FieldElement::new(4),
            FieldElement::new(3),
            FieldElement::new(2),
            FieldElement::new(1)
        ]);
    }
}
