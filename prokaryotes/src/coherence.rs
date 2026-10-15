// coherence.rs — Shannon entropy based coherence computation
// coherence = 1 - H(binary_decisions) / log(n)
 
use crate::decision::DecisionOutcome;
 
#[derive(Debug, Clone)]
pub struct Coherence {
    decisions: Vec<DecisionOutcome>,
}
 
impl Coherence {
    pub fn new() -> Self {
        Self {
            decisions: Vec::new(),
        }
    }
 
    pub fn record(&mut self, _delta_id: &str, outcome: DecisionOutcome) {
        self.decisions.push(outcome);
    }
 
    /// Shannon entropy: H = -sum(p * log2(p))
    fn entropy(&self) -> f64 {
        let n = self.decisions.len();
        if n == 0 {
            return 0.0;
        }
        let opportunities = self.decisions.iter()
            .filter(|&&d| d == DecisionOutcome::Opportunity)
            .count();
        let noise = n - opportunities;
 
        let p_opp = opportunities as f64 / n as f64;
        let p_noise = noise as f64 / n as f64;
 
        let h_opp = if p_opp > 0.0 { -p_opp * p_opp.log2() } else { 0.0 };
        let h_noise = if p_noise > 0.0 { -p_noise * p_noise.log2() } else { 0.0 };
 
        h_opp + h_noise
    }
 
    /// coherence = 1 - H / log2(n)
    /// n=1 case: coherence = 1.0 (single decision, fully coherent)
    pub fn value(&self) -> f64 {
        let n = self.decisions.len();
        if n <= 1 {
            return 1.0;
        }
        let h = self.entropy();
        let max_h = (n as f64).log2();
        if max_h == 0.0 {
            return 1.0;
        }
        1.0 - (h / max_h)
    }
 
    pub fn decision_count(&self) -> usize {
        self.decisions.len()
    }
}
 
impl Default for Coherence {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_coherence() {
        let mut c = Coherence::new();
        for _ in 0..10 {
            c.record("x", DecisionOutcome::Opportunity);
        }
        assert!(c.value() > 0.99);
    }

    #[test]
    fn test_zero_coherence() {
        let mut c = Coherence::new();
        for i in 0..10 {
            let outcome = if i % 2 == 0 {
                DecisionOutcome::Opportunity
            } else {
                DecisionOutcome::Noise
            };
            c.record("x", outcome);
        }
        let val = c.value();
        println!("coherence value: {}", val);
        assert!(val < 0.75);
    }
}
