//! Zoom for the whole interface.
//!
//! Layout lengths in this app are absolute pixels, so changing the window's
//! rem would leave the chrome where it is and only scale stock controls.
//! [`px`] multiplies a designed length by the current zoom. A length that
//! already came from the window (a mouse coordinate, a viewport size) is in
//! window pixels and must not pass through [`px`].

use std::sync::atomic::{AtomicU32, Ordering};

use gpui::Pixels;

/// Designed size. One press of the zoom shortcut moves one step.
pub const DEFAULT_UI_SCALE: f32 = 1.0;
pub const UI_SCALE_STEP: f32 = 0.1;

/// 70% to 200% of the designed layout.
const MIN_UI_SCALE_STEPS: i32 = -3;
const MAX_UI_SCALE_STEPS: i32 = 10;

static SCALE_BITS: AtomicU32 = AtomicU32::new(1.0f32.to_bits());

/// The zoom applied to designed lengths. Always finite and on the step ladder.
pub fn factor() -> f32 {
    clamp(f32::from_bits(SCALE_BITS.load(Ordering::Relaxed)))
}

/// Remember `scale` for every later [`px`] call. Clamps first.
pub fn set_factor(scale: f32) {
    SCALE_BITS.store(clamp(scale).to_bits(), Ordering::Relaxed);
}

/// A designed length, in window pixels at the current zoom.
pub fn px(value: f32) -> Pixels {
    gpui::px(value * factor())
}

/// The ladder step nearest `scale`, kept inside the zoom limits.
pub fn clamp(scale: f32) -> f32 {
    scale_from_steps(steps_of(scale))
}

/// Move `delta` steps from `scale`. Positive zooms in.
pub fn step(scale: f32, delta: i32) -> f32 {
    scale_from_steps(steps_of(scale).saturating_add(delta))
}

fn steps_of(scale: f32) -> i32 {
    if scale.is_nan() {
        return 0;
    }
    if scale.is_infinite() {
        return if scale.is_sign_positive() {
            MAX_UI_SCALE_STEPS
        } else {
            MIN_UI_SCALE_STEPS
        };
    }
    let steps = ((scale - DEFAULT_UI_SCALE) / UI_SCALE_STEP).round() as i32;
    steps.clamp(MIN_UI_SCALE_STEPS, MAX_UI_SCALE_STEPS)
}

fn scale_from_steps(steps: i32) -> f32 {
    let steps = steps.clamp(MIN_UI_SCALE_STEPS, MAX_UI_SCALE_STEPS);
    DEFAULT_UI_SCALE + steps as f32 * UI_SCALE_STEP
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zoom_steps_stay_on_the_ladder_and_inside_the_limits() {
        assert_eq!(step(1.0, 0), DEFAULT_UI_SCALE);
        assert_eq!(step(1.0, 1), scale_from_steps(1));
        assert_eq!(step(1.0, -1), scale_from_steps(-1));
        assert_eq!(step(1.0, 100), scale_from_steps(MAX_UI_SCALE_STEPS));
        assert_eq!(step(1.0, -100), scale_from_steps(MIN_UI_SCALE_STEPS));
        // A hand-edited value snaps to the nearest step.
        assert_eq!(clamp(1.13), scale_from_steps(1));
        assert_eq!(clamp(1.16), scale_from_steps(2));
        assert_eq!(clamp(f32::NAN), DEFAULT_UI_SCALE);
        assert_eq!(clamp(f32::INFINITY), scale_from_steps(MAX_UI_SCALE_STEPS));
        assert_eq!(
            clamp(f32::NEG_INFINITY),
            scale_from_steps(MIN_UI_SCALE_STEPS)
        );
    }
}
