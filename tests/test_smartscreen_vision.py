import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from smartscreen import vision as vision
ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'models/scareware'


class VisionCliGuards(unittest.TestCase):
    def run_cli(self, *arguments):
        return subprocess.run([sys.executable, str(ROOT/'smartscreen.py'), *map(str, arguments)],
                              capture_output=True, text=True)

    def test_reject_output_collisions_before_inference(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root/'assets'; bundle.mkdir()
            image = root/'image.png'; image.write_bytes(b'original-image')
            payload = bundle/'payload.ort'; payload.write_bytes(b'original-model')
            manifest = bundle/'assets.json'; manifest.write_text('{}')
            for output in (image, payload, manifest):
                before = output.read_bytes()
                result = self.run_cli('-o', output, 'score-image', image, '--assets', bundle)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(output.read_bytes(), before)
                self.assertNotIn('Traceback', result.stderr)

    def test_reject_hardlink_output_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root/'image.png'; image.write_bytes(b'original')
            output = root/'output.json'; os.link(image, output)
            result = self.run_cli('-o', output, 'score-image', image, '--assets', root/'assets')
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(image.read_bytes(), b'original')

    def test_prepare_cannot_silently_download(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self.run_cli('--prepare', root/'prepared', 'vision-download', root/'assets')
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse((root/'assets').exists())
            self.assertIn('do not support', result.stderr)

    def test_changed_fixture_fails_before_loading_assets(self):
        from tools.validate_vision import validate
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'scam.png').write_bytes(b'changed')
            (root/'fixtures.json').write_text(json.dumps({'schema_version': 1, 'cases': [
                {'file': 'scam.png', 'expected_classification': 'scam', 'sha256': '0'*64}]}))
            with self.assertRaisesRegex(ValueError, 'Fixture hash mismatch'):
                validate(root/'absent_assets', root)


class VisionModelContract(unittest.TestCase):
    def test_native_configuration_is_not_model_identity_or_l14_support(self):
        description = {'inputs': [{'name': 'input', 'type': 'tensor(float)', 'shape': ['batch', 3, 224, 224]}],
                       'outputs': [{'name': 'output', 'type': 'tensor(float)', 'shape': ['batch', 512]}]}
        b32 = vision.vision_compatibility(description, vector_keys=['vti-b-p32-visual'])
        self.assertTrue(b32['adapter_supported'])
        self.assertFalse(b32['matches_researched_model_bytes'])
        self.assertFalse(b32['interface_is_identity_proof'])
        missing = vision.vision_compatibility(description, vector_keys=[])
        self.assertFalse(missing['adapter_supported'])
        description['outputs'][0]['shape'][1] = 768
        l14 = vision.vision_compatibility(description, vector_keys=['vti-b-p32-visual'])
        self.assertTrue(l14['interface_recognized'])
        self.assertEqual(l14['interface_model_key'], 'vti-l-p14-visual')
        self.assertFalse(l14['adapter_supported'])
        self.assertFalse(l14['reference_vectors_present'])
        self.assertFalse(l14['alternate_native_configuration']['runtime_validated'])
        self.assertEqual(l14['evidence']['installer_required_filename'], 'vti-b-p32-visual.quant.ort')
        self.assertFalse(vision.vision_compatibility({})['interface_recognized'])

    def test_wrong_tensor_shape_is_rejected(self):
        class Tensor:
            name = 'input'
            type = 'tensor(float)'
            shape = [1, 3, 256, 256]
        class Session:
            def get_inputs(self): return [Tensor()]
            def get_outputs(self): return []
            def get_providers(self): return ['CPUExecutionProvider']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model = root/'model'; model.write_bytes(b'model')
            vectors = root/'vectors.json'; vectors.write_text('{}')
            with patch.object(vision, '_session', return_value=Session()):
                with self.assertRaisesRegex(ValueError, 'supports the researched B32'):
                    vision.ScarewareClassifier(model, vectors)

    def test_nonfinite_vector_json_rejected_before_loading_model(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'vectors.json'; path.write_text('{"value": NaN}')
            with self.assertRaisesRegex(ValueError, 'Non-finite'):
                vision.ScarewareClassifier(Path(directory)/'missing-model', path)


@unittest.skipUnless((ASSETS/'assets.json').exists(), 'Locally acquired signed model bundle is absent')
class RealVisionIntegration(unittest.TestCase):
    def test_preserved_positive_and_negative_controls(self):
        try:
            import PIL
            import onnxruntime
            import numpy
        except ImportError:
            self.skipTest('Optional vision runtime is not installed')
        from tools.validate_vision import validate
        with patch('urllib.request.urlopen', side_effect=AssertionError('Unexpected HTTP')):
            report = validate(ASSETS, require_baseline=True)
        self.assertTrue(report['passed'])
        self.assertTrue(report['baseline_assets_match'])
        self.assertEqual([row['classification'] for row in report['results']], ['scam', 'not_scam'])
        self.assertTrue(all(row['baseline_scores_match'] for row in report['results']))

    def test_signed_model_image_and_file_match_without_http(self):
        try:
            from PIL import Image
            import onnxruntime
            import numpy
        except ImportError:
            self.skipTest('Optional vision runtime is not installed')
        # Same opaque RGB pixels through PIL and PNG paths must produce identical
        # model output/scoring, while any tool HTTP request is an error.
        image = Image.new('RGB', (224, 224), (64, 128, 192))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'control.png'; image.save(path)
            with patch('urllib.request.urlopen', side_effect=AssertionError('Unexpected HTTP')):
                classifier = vision.ScarewareClassifier.from_bundle(ASSETS)
                direct = classifier.score_image(image, include_embedding=True)
                saved = classifier.score_image(path, include_embedding=True)
            self.assertEqual(direct['analysis'], saved['analysis'])
            self.assertEqual(len(direct['analysis']['normalized_embedding']), 512)
            self.assertEqual(len(direct['analysis']['tensor_sets']), 2)
            self.assertIsNone(direct['cloud_verdict'])
            self.assertIsNone(direct['browser_decision'])
            self.assertTrue(direct['model']['matches_researched_model'])
            json.dumps(direct, allow_nan=False)


if __name__ == '__main__':
    unittest.main()
