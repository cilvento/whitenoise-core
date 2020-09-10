//! # Base-2 Differential Privacy Module
//! Implements the exponential mechanism and other utilities for base-2 
//! Differential Privacy, based on 
//! [Ilvento '19](https://arxiv.org/abs/1912.04222).
//! 
//! ## Background
//! Although the exponential mechanism does not directly reveal the result of inexact
//! floating point computations, it has been shown to be vulnerable to attacks based
//! on rounding and no-op addition behavior of floating point arithmetic. To prevent
//! these issues, base-2 differential privacy uses arithmetic with base 2, rather than 
//! base e, allowing for an exact implementation.
//! 
//! ## Mechanism Details
//! * Base-2 exponential mechanism and parameter construction are described in
//!   this [paper](https://arxiv.org/abs/1912.04222).
//! * Proofs and pseudocode matching this implementation are available in the
//!   [whitepapers](https://github.com/opendifferentialprivacy/whitenoise-core/blob/develop/whitepapers/mechanisms/b2_exponential_mechanism_proofs.pdf).
//!  * Mechanism does not scale privacy parameters based on sensitivity, it is 
//!    the caller's responsibility to do so. 
//! ## Example Usage
//! **Converting a base-e parameter to base-2**
//! ```
//! use whitenoise_runtime::utilities::b2dp::Eta;
//! # use whitenoise_validator::errors::*;
//! # fn main() -> Result<()> {
//! let epsilon = 1.25;
//! let eta = Eta::from_epsilon(epsilon)?;
//! # Ok(()) }
//! ```
//! **Running the exponential mechanism**
//! 
//! Run the exponential mechanism with utility function `utility_fn`.
//! ```
//! use whitenoise_runtime::utilities::b2dp::{exponential_mechanism, 
//!                                           Eta, GeneratorOpenSSL};
//! # use whitenoise_validator::errors::*;
//! 
//! # fn main() -> Result<()> {
//! fn util_fn (x: &u32) -> f64 {
//!     return ((*x as f64)-0.0).abs();
//! }
//! let eta = Eta::new(1,1,1)?; // Construct a privacy parameter
//! let utility_min = 0; // Set bounds on the utility and outcomes
//! let utility_max = 10;
//! let max_outcomes = 10;
//! let rng = GeneratorOpenSSL {};
//! let outcomes: Vec<u32> = (0..max_outcomes).collect();
//! let sample = exponential_mechanism(eta, &outcomes, util_fn, 
//!                                     utility_min, utility_max, 
//!                                     max_outcomes,
//!                                     rng, 
//!                                     Default::default())?;
//! # Ok(()) 
//! # }
//! ```
//! **Scaling based on utility function sensitivity**
//! Given a utility function with sensitivity `alpha`, the `exponential_mechanism` 
//! implementation is `2*alpha*ln(2)*eta` base-e DP. To explicitly scale by `alpha`
//! the caller can either modify the `eta` used or the utility function.
//! ```
//! use whitenoise_runtime::utilities::b2dp::{exponential_mechanism, 
//!                                           Eta, GeneratorOpenSSL};
//! use whitenoise_validator::errors::*;
//! # fn main() -> Result<()> {
//! // Scale the privacy parameter to account for the utility sensitivity
//! let epsilon = 1.25;
//! let eta = Eta::from_epsilon(epsilon)?;
//! let alpha = 2.0;
//! let eta_scaled = Eta::from_epsilon(epsilon/alpha)?;
//! // Or scale the utility function to reduce sensitivity
//! let alpha = 2.0;
//! 
//! fn util_fn (x: &u32) -> f64 {
//!     return (2.0*(*x as f64)-0.0).abs();
//! }
//! let scaled_utility_fn = |x: &f64| -> f64 { *x/alpha };
//! # Ok(())
//! # }
//! ```

/// Base-2 Differential Privacy Utilities
pub mod b2utilities;
/// Base-2 Differential Privacy Mechanisms
pub mod b2mechanisms;

// Parameters and main exponential mechanism functionality
pub use b2utilities::params::Eta as Eta;
pub use b2utilities::exactarithmetic::randomized_round as randomized_round;
pub use b2utilities::exactarithmetic::normalized_sample as normalized_sample;
pub use b2utilities::randomness::GeneratorOpenSSL;
pub use b2mechanisms::exponential::exponential_mechanism as exponential_mechanism;
pub use b2mechanisms::exponential::ExponentialOptions;