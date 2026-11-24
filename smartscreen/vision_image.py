"""Offline screenshot preprocessing recovered from Edge 158 ARM64.

The resize filter and convolution algorithms are adapted from Chromium's
skia/ext/image_operations.cc and convolver.cc. They use signed 14-bit fixed
point coefficients and an intermediate uint8 image, unlike Pillow Lanczos.
Native arithmetic/geometry evidence is in analysis/scareware_native/.

Copyright 2012 The Chromium Authors
Copyright 2015 The Chromium Authors
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.
* Neither the name of Google LLC nor the names of its contributors may be
  used to endorse or promote products derived from this software without
  specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
"""

from functools import lru_cache
import math
from pathlib import Path
import struct

SCALING_MODES = ("Resize", "CropCenter", "ShortEdge")
RESIZE_METHODS = ("resize_good", "resize_better", "resize_best", "resize_box",
                  "resize_hamming1", "resize_lanczos3")
TARGET_SIZE = 224
MAX_PIXELS = 32_000_000
MAX_DIMENSION = 16_384
MEAN = (0.48145467042922974, 0.45782750844955444, 0.40821072459220886)
STD = (0.2686295509338379, 0.2613025903701782, 0.27577710151672363)


def _f32(value):
    return struct.unpack("<f", struct.pack("<f", value))[0]


def _algorithm(method):
    if method not in RESIZE_METHODS:
        raise ValueError("Unsupported resize_method; choose " + ", ".join(RESIZE_METHODS))
    if method in ("resize_good", "resize_better"):
        return "hamming1"
    if method == "resize_best":
        return "lanczos3"
    return method.removeprefix("resize_")


def crop_geometry(width, height, scaling="ShortEdge"):
    """Return the recovered source rectangle [left, top, right, bottom]."""
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 1
           for value in (width, height)):
        raise ValueError("Image dimensions must be positive integers")
    if width > MAX_DIMENSION or height > MAX_DIMENSION or width * height > MAX_PIXELS:
        raise ValueError("Image exceeds the supported dimensions or pixel budget")
    if scaling == "LongEdge":
        raise ValueError("LongEdge padding contents are not validated; use ShortEdge or Resize")
    if scaling not in SCALING_MODES:
        raise ValueError("Unsupported scaling; choose " + ", ".join(SCALING_MODES))
    if scaling == "Resize":
        return [0, 0, width, height]
    if scaling == "CropCenter":
        if min(width, height) < TARGET_SIZE:
            raise ValueError("CropCenter requires both source dimensions to be at least 224")
        left, top = (width - TARGET_SIZE) // 2, (height - TARGET_SIZE) // 2
        return [left, top, left + TARGET_SIZE, top + TARGET_SIZE]
    size = min(width, height)
    left = (width - size) // 2
    # Edge 158's portrait branch deliberately leaves top at zero.
    top = (height - size) // 2 if height <= width else 0
    return [left, top, left + size, top + size]


def _filter_value(position, algorithm):
    if algorithm == "box":
        return 1.0 if -0.5 <= position < 0.5 else 0.0
    support = 1.0 if algorithm == "hamming1" else 3.0
    if abs(position) >= support:
        return 0.0
    if abs(position) < 2.0 ** -23:
        return 1.0
    xpi = _f32(position * _f32(math.pi))
    sinc = _f32(_f32(math.sin(xpi)) / xpi)
    if algorithm == "hamming1":
        cosine = _f32(math.cos(xpi))
        window = _f32(_f32(cosine * _f32(0.46)) + _f32(0.54))
        return _f32(sinc * window)
    third = _f32(xpi / 3.0)
    return _f32(_f32(sinc * _f32(math.sin(third))) / third)


@lru_cache(maxsize=32)
def _coefficients(source_size, destination_size, algorithm):
    """Return immutable (source offset, signed14 coefficient tuple) rows."""
    scale = _f32(_f32(destination_size) / _f32(source_size))
    clamped = min(1.0, scale)
    support = {"box": 0.5, "hamming1": 1.0, "lanczos3": 3.0}[algorithm]
    source_support, inverse = _f32(support / clamped), _f32(1.0 / scale)
    result = []
    for destination in range(destination_size):
        pixel = _f32(_f32(_f32(destination) + 0.5) * inverse)
        begin = max(0, math.floor(_f32(pixel - source_support)))
        end = min(source_size - 1, math.ceil(_f32(pixel + source_support)))
        values = []
        total = 0.0
        for current in range(begin, end + 1):
            distance = _f32(_f32(_f32(_f32(current) + 0.5) - pixel) * clamped)
            value = _filter_value(distance, algorithm)
            values.append(value)
            total = _f32(total + value)
        if not values or not math.isfinite(total) or total <= 0:
            raise ValueError("Unable to construct a valid resize filter")
        fixed = [math.trunc(_f32(_f32(value / total) * 16384.0)) for value in values]
        fixed[len(fixed) // 2] += 16384 - sum(fixed)
        # Skia trims zero end coefficients before convolution.
        first = next(index for index, value in enumerate(fixed) if value)
        last = len(fixed) - next(index for index, value in enumerate(reversed(fixed)) if value)
        result.append((begin + first, tuple(fixed[first:last])))
    return tuple(result)


def resize_rgb(pixels, width=TARGET_SIZE, height=TARGET_SIZE, *, resize_method="resize_lanczos3"):
    """Resize an opaque uint8 HWC RGB array with Skia's fixed-point algorithm.

    Python math supplies sin/cos, rounded to float32. Full Windows libm and
    SIMD implementation parity is not asserted for every possible dimension.
    """
    import numpy as np

    algorithm = _algorithm(resize_method)
    if (not isinstance(pixels, np.ndarray) or pixels.dtype != np.uint8 or
            pixels.ndim != 3 or pixels.shape[2] != 3):
        raise ValueError("pixels must be a uint8 HWC RGB NumPy array")
    source_height, source_width = pixels.shape[:2]
    crop_geometry(source_width, source_height, "Resize")
    crop_geometry(width, height, "Resize")
    if (source_width, source_height) == (width, height):
        return np.array(pixels, copy=True, order="C")
    horizontal = np.empty((source_height, width, 3), dtype=np.uint8)
    # A byte intermediate and arithmetic shifts (without a rounding offset)
    # reproduce Chromium's horizontal then vertical integer convolution.
    for destination, (start, coefficients) in enumerate(_coefficients(source_width, width, algorithm)):
        taps = np.asarray(coefficients, dtype=np.int32)
        accumulated = (pixels[:, start:start + len(taps), :].astype(np.int32) *
                       taps[None, :, None]).sum(axis=1, dtype=np.int32)
        horizontal[:, destination, :] = np.clip(accumulated >> 14, 0, 255)
    output = np.empty((height, width, 3), dtype=np.uint8)
    for destination, (start, coefficients) in enumerate(_coefficients(source_height, height, algorithm)):
        taps = np.asarray(coefficients, dtype=np.int32)
        accumulated = (horizontal[start:start + len(taps), :, :].astype(np.int32) *
                       taps[:, None, None]).sum(axis=0, dtype=np.int32)
        output[destination, :, :] = np.clip(accumulated >> 14, 0, 255)
    return output


def normalize_rgb(pixels):
    """Convert uint8 RGB into native float32 planar RGB, without resizing."""
    import numpy as np

    if (not isinstance(pixels, np.ndarray) or pixels.dtype != np.uint8 or
            pixels.ndim != 3 or pixels.shape[2] != 3):
        raise ValueError("pixels must be a uint8 HWC RGB NumPy array")
    output = pixels.astype(np.float32)
    output /= np.float32(255.0)
    output -= np.asarray(MEAN, dtype=np.float32)
    output /= np.asarray(STD, dtype=np.float32)
    return np.ascontiguousarray(output.transpose(2, 0, 1)[None, :, :, :])


def prepare_image(image, *, scaling="ShortEdge", resize_method="resize_lanczos3"):
    """Prepare an opaque screenshot path/PIL image for the recovered visual model.

    EXIF orientation is applied for local image usability. ICC/gamma transforms
    are not applied. Native inputs are browser screenshot pixels, so the file
    decoder/EXIF handling is an explicit adapter, not a browser capture claim.
    """
    try:
        import numpy as np
        from PIL import Image, ImageOps
    except ImportError as error:
        raise RuntimeError("Image inference needs NumPy and Pillow; use .venv-vision") from error
    _algorithm(resize_method)
    opened = None
    try:
        if isinstance(image, (str, Path)):
            opened = Image.open(image)
            source = opened
        elif isinstance(image, Image.Image):
            source = image
        else:
            raise ValueError("image must be a local path or PIL image")
        crop_geometry(*source.size, scaling)
        if getattr(source, "n_frames", 1) != 1:
            raise ValueError("Animated or multi-frame images require an explicit single screenshot")
        orientation = source.getexif().get(274, 1)
        oriented = ImageOps.exif_transpose(source)
        width, height = oriented.size
        rectangle = crop_geometry(width, height, scaling)
        rgba = oriented.convert("RGBA")
        if rgba.getchannel("A").getextrema() != (255, 255):
            raise ValueError("Use an opaque screenshot; translucent-pixel premultiplication is not validated")
        rgb = np.asarray(rgba.convert("RGB"), dtype=np.uint8)
        left, top, right, bottom = rectangle
        resized = resize_rgb(rgb[top:bottom, left:right], resize_method=resize_method)
        tensor = normalize_rgb(resized)
        metadata = {
            "source_size": [width, height], "scaling": scaling,
            "resize_method": resize_method, "resize_algorithm": _algorithm(resize_method),
            "crop_rectangle": rectangle, "output_size": [TARGET_SIZE, TARGET_SIZE],
            "tensor_shape": list(tensor.shape), "tensor_dtype": "float32",
            "channel_order": "RGB", "layout": "NCHW", "mean": list(MEAN), "std": list(STD),
            "exif_orientation_applied": orientation not in (None, 1),
            "file_adapter": "Pillow decode; EXIF orientation applied; ICC/gamma transforms not applied; opaque only",
            "native_parity": "Edge158 ARM64 geometry and float32 normalization validated; fixed-point filters and scalar convolution matched bounded native fixtures with documented math/conversion shims; Windows sinf/cosf and SIMD parity not established for all inputs",
            "evidence": "analysis/scareware_native/findings.json",
        }
        return tensor, metadata
    finally:
        if opened is not None:
            opened.close()
