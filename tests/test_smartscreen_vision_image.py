"""Offline image-transform checks against independently emulated Edge fixtures."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from smartscreen.vision_image import (_coefficients, crop_geometry, prepare_image,
                                     normalize_rgb, resize_rgb)

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "tests/fixtures/native"
HAS_IMAGE_DEPS = bool(importlib.util.find_spec("numpy") and importlib.util.find_spec("PIL"))


class GeometryTests(unittest.TestCase):
    def test_native_rectangles(self):
        rows = json.loads((EVIDENCE / "transforms_native.json").read_text())["geometry"]
        for row in rows:
            mode, width, height = row["mode"], row["source_width"], row["source_height"]
            with self.subTest(mode=mode, width=width, height=height):
                if mode in (1, 2) and row["crop_within_source"]:
                    self.assertEqual(crop_geometry(width, height, ("Resize", "CropCenter", "ShortEdge")[mode]), row["expected"])
                elif mode == 0:
                    self.assertEqual(crop_geometry(width, height, "Resize"), [0, 0, width, height])

    def test_portrait_crop_is_top_aligned(self):
        self.assertEqual(crop_geometry(480, 641), [0, 0, 480, 480])
        self.assertEqual(crop_geometry(641, 480), [80, 0, 560, 480])

    def test_unsupported_geometry_and_budget(self):
        for arguments in [(640, 480, "LongEdge"), (100, 224, "CropCenter"),
                          (0, 400, "Resize"), (True, 400, "Resize"),
                          (20000, 20000, "Resize"), (400, 400, "unknown")]:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                crop_geometry(*arguments)

    def test_coefficient_brightness_and_aliases(self):
        for algorithm in ("box", "hamming1", "lanczos3"):
            for source, destination in ((7, 3), (3, 7), (480, 224), (224, 224)):
                for offset, coefficients in _coefficients(source, destination, algorithm):
                    self.assertEqual(sum(coefficients), 16384)
                    self.assertGreaterEqual(offset, 0)
                    self.assertLessEqual(offset + len(coefficients), source)

    def test_native_fixed_point_coefficients(self):
        rows = json.loads((EVIDENCE / "coefficients_native.json").read_text())["cases"]
        for row in rows:
            algorithm = {3: "box", 4: "hamming1", 5: "lanczos3"}[row["method"]]
            actual = _coefficients(row["source"], row["destination"], algorithm)
            self.assertEqual(len(actual), len(row["filters"]))
            for (offset, coefficients), native in zip(actual, row["filters"]):
                untrimmed = native["values"]
                first = next(i for i, value in enumerate(untrimmed) if value)
                last = len(untrimmed) - next(i for i, value in enumerate(reversed(untrimmed)) if value)
                self.assertEqual((offset, coefficients),
                                 (native["offset"] + first, tuple(untrimmed[first:last])))


@unittest.skipUnless(HAS_IMAGE_DEPS, "optional NumPy/Pillow image dependencies unavailable")
class ImageTests(unittest.TestCase):
    def setUp(self):
        import numpy as np
        from PIL import Image
        self.np, self.Image = np, Image

    def test_native_normalization_bits(self):
        fixture = json.loads((EVIDENCE / "transforms_native.json").read_text())
        for row in fixture["pixels"]:
            bgra = self.np.array(row["bgra"], dtype=self.np.uint8)
            rgb = bgra[:, [2, 1, 0]][None, :, :]
            got = normalize_rgb(rgb)
            expected = self.np.asarray(row["native_rgb_planar"], dtype=self.np.float32)
            self.assertEqual(got.ravel().tobytes(), expected.tobytes())
            self.assertTrue(got.flags.c_contiguous)

    def test_resize_constant_and_identity(self):
        constant = self.np.empty((9, 7, 3), dtype=self.np.uint8)
        constant[:] = [17, 128, 243]
        for method in ("resize_box", "resize_hamming1", "resize_lanczos3"):
            resized = resize_rgb(constant, 11, 5, resize_method=method)
            self.np.testing.assert_array_equal(resized, self.np.broadcast_to([17, 128, 243], (5, 11, 3)))
        original = self.np.arange(7 * 9 * 3, dtype=self.np.uint8).reshape(7, 9, 3)
        self.np.testing.assert_array_equal(resize_rgb(original, 9, 7), original)

    def test_native_scalar_convolution_bytes(self):
        fixtures = json.loads((EVIDENCE / "convolution_fixtures.json").read_text())
        captures = {row["name"]: row for row in
                    json.loads((EVIDENCE / "convolution_native.json").read_text())["cases"]}
        for fixture in fixtures:
            with self.subTest(name=fixture["name"]):
                width, height = fixture["source_size"]
                bgra = self.np.asarray(fixture["bgra"], dtype=self.np.uint8).reshape(height, width, 4)
                actual = resize_rgb(bgra[:, :, [2, 1, 0]], *fixture["destination_size"],
                                    resize_method="resize_" + fixture["algorithm"])
                width, height = fixture["destination_size"]
                native = self.np.asarray(captures[fixture["name"]]["native_bgra"],
                                         dtype=self.np.uint8).reshape(height, width, 4)
                self.np.testing.assert_array_equal(actual, native[:, :, [2, 1, 0]])

    def test_shortedge_uses_top_of_portrait(self):
        pixels = self.np.zeros((448, 224, 3), dtype=self.np.uint8)
        pixels[:224, :, :] = [255, 0, 0]
        pixels[224:, :, :] = [0, 255, 0]
        image = self.Image.fromarray(pixels)
        before = image.tobytes()
        tensor, metadata = prepare_image(image)
        expected = normalize_rgb(pixels[:224])
        self.np.testing.assert_array_equal(tensor, expected)
        self.assertEqual(metadata["source_size"], [224, 448])
        self.assertEqual(metadata["crop_rectangle"], [0, 0, 224, 224])
        self.assertEqual(tensor.shape, (1, 3, 224, 224))
        self.assertEqual(image.tobytes(), before)

    def test_path_and_exif_adapter(self):
        image = self.Image.new("RGB", (224, 448), (33, 66, 99))
        exif = image.getexif()
        exif[274] = 6
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "orientation.png"
            image.save(path, exif=exif)
            _, metadata = prepare_image(path)
        self.assertEqual(metadata["source_size"], [448, 224])
        self.assertTrue(metadata["exif_orientation_applied"])

    def test_transparent_and_invalid_inputs(self):
        for image in (self.Image.new("RGBA", (224, 224), (255, 0, 0, 128)), 42):
            with self.assertRaises(ValueError):
                prepare_image(image)
        with self.assertRaises(ValueError):
            prepare_image(self.Image.new("RGB", (224, 224)), resize_method="pillow_lanczos")

    def test_resizer_validates_dtype_and_dimensions(self):
        with self.assertRaises(ValueError):
            resize_rgb(self.np.zeros((4, 4, 3), dtype=self.np.float32))
        with self.assertRaises(ValueError):
            resize_rgb(self.np.zeros((4, 4, 4), dtype=self.np.uint8))


if __name__ == "__main__":
    unittest.main()
