//! Algebraic Intermediate Representation (AIR) for the STARK protocol
use crate::zk::stark::field::FieldElement;
use std::error::Error;

/// Constraint for the algebraic execution trace
#[derive(Debug, Clone)]
pub enum Constraint {
    /// Equality constraint: trace[step][register_1] == trace[step][register_2]
    Equal(usize, usize, usize),
    
    /// Addition constraint: trace[step][register_1] + trace[step][register_2] == trace[step][register_3]
    Add(usize, usize, usize, usize),
    
    /// Multiplication constraint: trace[step][register_1] * trace[step][register_2] == trace[step][register_3]
    Multiply(usize, usize, usize, usize),
    
    /// Transition constraint: trace[step+1][register_1] == expression
    Transition(usize, usize, Box<Expression>),
    
    /// Boundary constraint: trace[step][register] == value
    Boundary(usize, usize, FieldElement),
}

/// Expression in an algebraic constraint
#[derive(Debug, Clone)]
pub enum Expression {
    /// Constant value
    Constant(FieldElement),
    
    /// Register value: trace[step][register]
    Register(usize, usize),
    
    /// Addition: left + right
    Add(Box<Expression>, Box<Expression>),
    
    /// Subtraction: left - right
    Subtract(Box<Expression>, Box<Expression>),
    
    /// Multiplication: left * right
    Multiply(Box<Expression>, Box<Expression>),
    
    /// Division: left / right
    Divide(Box<Expression>, Box<Expression>),
}

impl Expression {
    /// Create a constant expression
    pub fn constant(value: u64) -> Self {
        Self::Constant(FieldElement::new(value))
    }
    
    /// Create a register reference expression
    pub fn register(step: usize, register: usize) -> Self {
        Self::Register(step, register)
    }
    
    /// Add two expressions
    pub fn add(left: Expression, right: Expression) -> Self {
        Self::Add(Box::new(left), Box::new(right))
    }
    
    /// Subtract right from left
    pub fn subtract(left: Expression, right: Expression) -> Self {
        Self::Subtract(Box::new(left), Box::new(right))
    }
    
    /// Multiply two expressions
    pub fn multiply(left: Expression, right: Expression) -> Self {
        Self::Multiply(Box::new(left), Box::new(right))
    }
    
    /// Divide left by right
    pub fn divide(left: Expression, right: Expression) -> Self {
        Self::Divide(Box::new(left), Box::new(right))
    }
    
    /// Evaluate the expression given a trace
    pub fn evaluate(&self, trace: &[Vec<FieldElement>]) -> Result<FieldElement, Box<dyn Error>> {
        match self {
            Self::Constant(value) => Ok(*value),
            
            Self::Register(step, register) => {
                if *step >= trace.len() {
                    return Err(format!("Step {} out of bounds in trace", step).into());
                }
                
                if *register >= trace[*step].len() {
                    return Err(format!("Register {} out of bounds in trace[{}]", register, step).into());
                }
                
                Ok(trace[*step][*register])
            },
            
            Self::Add(left, right) => {
                let left_value = left.evaluate(trace)?;
                let right_value = right.evaluate(trace)?;
                Ok(left_value + right_value)
            },
            
            Self::Subtract(left, right) => {
                let left_value = left.evaluate(trace)?;
                let right_value = right.evaluate(trace)?;
                Ok(left_value - right_value)
            },
            
            Self::Multiply(left, right) => {
                let left_value = left.evaluate(trace)?;
                let right_value = right.evaluate(trace)?;
                Ok(left_value * right_value)
            },
            
            Self::Divide(left, right) => {
                let left_value = left.evaluate(trace)?;
                let right_value = right.evaluate(trace)?;
                
                if right_value == FieldElement::zero() {
                    return Err("Division by zero in expression".into());
                }
                
                Ok(left_value / right_value)
            },
        }
    }
}

/// Algebraic Intermediate Representation (AIR) for a computation
pub struct AIR {
    /// Number of registers in the execution trace
    pub num_registers: usize,
    
    /// Number of steps in the execution trace
    pub num_steps: usize,
    
    /// Constraints that define the computation
    pub constraints: Vec<Constraint>,
}

impl AIR {
    /// Create a new AIR for a computation
    pub fn new(num_registers: usize, num_steps: usize) -> Self {
        Self {
            num_registers,
            num_steps,
            constraints: Vec::new(),
        }
    }
    
    /// Add a constraint to the AIR
    pub fn add_constraint(&mut self, constraint: Constraint) {
        self.constraints.push(constraint);
    }
    
    /// Verify that a trace satisfies all constraints
    pub fn verify_trace(&self, trace: &[Vec<FieldElement>]) -> Result<bool, Box<dyn Error>> {
        // Check trace dimensions
        if trace.len() != self.num_steps {
            return Err(format!(
                "Trace has {} steps, expected {}", 
                trace.len(), 
                self.num_steps
            ).into());
        }
        
        for (i, step) in trace.iter().enumerate() {
            if step.len() != self.num_registers {
                return Err(format!(
                    "Step {} has {} registers, expected {}", 
                    i, 
                    step.len(), 
                    self.num_registers
                ).into());
            }
        }
        
        // Check all constraints
        for constraint in &self.constraints {
            match constraint {
                Constraint::Equal(step, reg1, reg2) => {
                    if *step >= trace.len() || *reg1 >= trace[*step].len() || *reg2 >= trace[*step].len() {
                        return Err("Invalid indices in Equal constraint".into());
                    }
                    
                    if trace[*step][*reg1] != trace[*step][*reg2] {
                        return Ok(false);
                    }
                },
                
                Constraint::Add(step, reg1, reg2, reg3) => {
                    if *step >= trace.len() || 
                       *reg1 >= trace[*step].len() || 
                       *reg2 >= trace[*step].len() || 
                       *reg3 >= trace[*step].len() {
                        return Err("Invalid indices in Add constraint".into());
                    }
                    
                    if trace[*step][*reg1] + trace[*step][*reg2] != trace[*step][*reg3] {
                        return Ok(false);
                    }
                },
                
                Constraint::Multiply(step, reg1, reg2, reg3) => {
                    if *step >= trace.len() || 
                       *reg1 >= trace[*step].len() || 
                       *reg2 >= trace[*step].len() || 
                       *reg3 >= trace[*step].len() {
                        return Err("Invalid indices in Multiply constraint".into());
                    }
                    
                    if trace[*step][*reg1] * trace[*step][*reg2] != trace[*step][*reg3] {
                        return Ok(false);
                    }
                },
                
                Constraint::Transition(step, reg, expr) => {
                    if *step >= trace.len() - 1 || *reg >= trace[*step + 1].len() {
                        return Err("Invalid indices in Transition constraint".into());
                    }
                    
                    let expected = expr.evaluate(trace)?;
                    if trace[*step + 1][*reg] != expected {
                        return Ok(false);
                    }
                },
                
                Constraint::Boundary(step, reg, value) => {
                    if *step >= trace.len() || *reg >= trace[*step].len() {
                        return Err("Invalid indices in Boundary constraint".into());
                    }
                    
                    if trace[*step][*reg] != *value {
                        return Ok(false);
                    }
                },
            }
        }
        
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fibonacci_air() -> Result<(), Box<dyn Error>> {
        // Create an AIR for the Fibonacci sequence
        let mut air = AIR::new(2, 10);
        
        // Initial conditions: F[0] = 0, F[1] = 1
        air.add_constraint(Constraint::Boundary(0, 0, FieldElement::new(0)));
        air.add_constraint(Constraint::Boundary(0, 1, FieldElement::new(1)));
        
        // Transition constraint: F[n+1] = F[n] + F[n-1]
        // In terms of our registers:
        // trace[i+1][0] = trace[i][1]
        // trace[i+1][1] = trace[i][0] + trace[i][1]
        
        // Register 0 at step i+1 equals register 1 at step i
        for i in 0..9 {
            air.add_constraint(Constraint::Transition(
                i,
                0,
                Box::new(Expression::Register(i, 1))
            ));
        }
        
        // Register 1 at step i+1 equals register 0 + register 1 at step i
        for i in 0..9 {
            air.add_constraint(Constraint::Transition(
                i,
                1,
                Box::new(Expression::add(
                    Expression::Register(i, 0),
                    Expression::Register(i, 1)
                ))
            ));
        }
        
        // Create a valid Fibonacci trace
        let mut trace = vec![vec![FieldElement::zero(); 2]; 10];
        trace[0][0] = FieldElement::new(0); // F[0]
        trace[0][1] = FieldElement::new(1); // F[1]
        
        for i in 1..10 {
            trace[i][0] = trace[i-1][1];                   // F[i] = F[i-1]
            trace[i][1] = trace[i-1][0] + trace[i-1][1];  // F[i+1] = F[i-1] + F[i]
        }
        
        // Verify the trace
        let is_valid = air.verify_trace(&trace)?;
        assert!(is_valid, "Valid Fibonacci trace should be accepted");
        
        // Create an invalid trace by changing one value
        let mut invalid_trace = trace.clone();
        invalid_trace[5][1] = FieldElement::new(99); // Wrong value
        
        let is_valid = air.verify_trace(&invalid_trace)?;
        assert!(!is_valid, "Invalid trace should be rejected");
        
        Ok(())
    }
}
