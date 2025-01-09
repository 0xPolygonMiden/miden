#[cfg(all(feature = "metal", target_arch = "aarch64", target_os = "macos"))]
pub mod metal;

#[cfg(all(feature = "cuda", target_arch = "x86_64"))]
pub mod cuda;
