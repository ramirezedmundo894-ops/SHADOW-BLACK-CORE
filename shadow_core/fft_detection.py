"""Configurable FFT detector for periodic activity/beaconing.

This is a mathematical feature detector, not a Frida detector or a trained AI model.
It expects evenly sampled values; callers must resample timestamps before using it.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Sequence


@dataclass(frozen=True)
class FFTConfig:
    sample_rate_hz: float
    min_frequency_hz: float = 0.05
    max_frequency_hz: float | None = None
    peak_power_ratio_threshold: float = 0.5
    window: str = "hann"
    min_samples: int = 32
    max_samples: int = 8192

    def validate(self, sample_count: int) -> None:
        if not math.isfinite(self.sample_rate_hz) or self.sample_rate_hz <= 0:
            raise ValueError("sample_rate_hz must be finite and positive")
        nyquist = self.sample_rate_hz / 2
        upper = nyquist if self.max_frequency_hz is None else self.max_frequency_hz
        if (not math.isfinite(self.min_frequency_hz) or not math.isfinite(upper)
                or self.min_frequency_hz <= 0 or upper <= self.min_frequency_hz or upper > nyquist):
            raise ValueError("frequency band must be positive, ordered, and at or below Nyquist")
        if (not math.isfinite(self.peak_power_ratio_threshold)
                or not 0 < self.peak_power_ratio_threshold <= 1):
            raise ValueError("peak_power_ratio_threshold must be in (0, 1]")
        if self.window not in {"hann", "hamming", "rectangular"}:
            raise ValueError("window must be hann, hamming, or rectangular")
        if not self.min_samples <= sample_count <= self.max_samples:
            raise ValueError(f"sample_count must be between {self.min_samples} and {self.max_samples}")


def _fft_radix2(values: list[complex]) -> list[complex]:
    """Iterative radix-2 Cooley-Tukey FFT, O(N log N), with no opaque dependency."""
    n = len(values)
    if n == 0 or n & (n - 1):
        raise ValueError("FFT input length must be a non-zero power of two")
    out = values[:]
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            out[i], out[j] = out[j], out[i]
    size = 2
    while size <= n:
        angle = -2.0 * math.pi / size
        root = complex(math.cos(angle), math.sin(angle))
        half = size // 2
        for start in range(0, n, size):
            factor = 1 + 0j
            for offset in range(half):
                even = out[start + offset]
                odd = factor * out[start + offset + half]
                out[start + offset] = even + odd
                out[start + offset + half] = even - odd
                factor *= root
        size <<= 1
    return out


def _window_value(name: str, index: int, count: int) -> float:
    if name == "rectangular":
        return 1.0
    phase = 2 * math.pi * index / (count - 1)
    if name == "hann":
        return 0.5 - 0.5 * math.cos(phase)
    return 0.54 - 0.46 * math.cos(phase)  # Hamming


def analyze_periodicity(samples: Sequence[float], config: FFTConfig) -> dict:
    """Return the strongest in-band FFT peak and its share of in-band power.

    Input is mean-centered then windowed. Zero-padding to the next power of two
    makes the radix-2 transform fast; it does not add information/resolution.
    """
    count = len(samples)
    config.validate(count)
    data = [float(value) for value in samples]
    if any(not math.isfinite(value) for value in data):
        raise ValueError("samples must contain only finite values")
    # Normalize before averaging/squaring to avoid overflow from arbitrary finite input magnitudes.
    scale = max((abs(value) for value in data), default=0.0)
    normalized = [value / scale for value in data] if scale else data
    mean = math.fsum(normalized) / count
    centered = [(value - mean) * _window_value(config.window, i, count)
                for i, value in enumerate(normalized)]
    n_fft = 1 << (count - 1).bit_length()
    transformed = _fft_radix2([complex(value, 0.0) for value in centered] + [0j] * (n_fft - count))
    upper = config.sample_rate_hz / 2 if config.max_frequency_hz is None else config.max_frequency_hz
    first_bin = max(1, math.ceil(config.min_frequency_hz * n_fft / config.sample_rate_hz))
    last_bin = min(n_fft // 2, math.floor(upper * n_fft / config.sample_rate_hz))
    if first_bin > last_bin:
        raise ValueError("configured frequency band contains no FFT bins")
    if last_bin - first_bin + 1 < 3:
        raise ValueError("configured frequency band must span at least three FFT bins")
    powers = [(k, transformed[k].real ** 2 + transformed[k].imag ** 2)
              for k in range(first_bin, last_bin + 1)]
    total_power = sum(power for _, power in powers)
    peak_bin, peak_power = max(powers, key=lambda item: item[1])
    ratio = peak_power / total_power if total_power > 0 else 0.0
    frequency = peak_bin * config.sample_rate_hz / n_fft
    detected = total_power > 0 and ratio >= config.peak_power_ratio_threshold
    return {
        "detected": detected,
        "dominant_frequency_hz": frequency,
        "peak_power_ratio": round(ratio, 8),
        "threshold": config.peak_power_ratio_threshold,
        "window": config.window,
        "sample_rate_hz": config.sample_rate_hz,
        "sample_count": count,
        "fft_size": n_fft,
        "nominal_resolution_hz": config.sample_rate_hz / count,
        "band_hz": [config.min_frequency_hz, upper],
        "band_bin_count": len(powers),
        "method": "mean_centered_windowed_radix2_fft",
    }
