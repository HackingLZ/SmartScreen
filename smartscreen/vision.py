"""Local inference with Edge's extracted scareware image model.

The optional ONNX Runtime/Pillow/NumPy dependencies are loaded on demand.
No image or inference result is sent to Microsoft. Results describe the local
model and dataset, not a SmartScreen cloud verdict or a browser policy decision.
"""
import hashlib
import json
from pathlib import Path
import time

MODEL_KEY = 'vti-b-p32-visual'
KNOWN_MODEL_SHA256 = '2ffbab5d3623d5e0ccd00d5bf3f1f20a600ee0edc560790de680d7dc8cba02c8'


def vision_compatibility(description, *, model_sha256=None, vector_keys=None):
    """Compare a runtime interface to recovered native configurations.

    Recognizing dimensions is not proof of model identity. L14 is a native
    configuration branch, but no matching model or vectors were recovered from
    the authenticated components, so this adapter does not enable L14 inference.
    """
    inputs, outputs = description.get('inputs', []), description.get('outputs', [])
    key = None
    if (len(inputs) == 1 and len(outputs) == 1 and
            inputs[0].get('name') == 'input' and inputs[0].get('type') == 'tensor(float)' and
            isinstance(inputs[0].get('shape'), list) and len(inputs[0]['shape']) == 4 and
            inputs[0]['shape'][1:] == [3, 224, 224] and
            outputs[0].get('name') == 'output' and outputs[0].get('type') == 'tensor(float)' and
            isinstance(outputs[0].get('shape'), list) and len(outputs[0]['shape']) == 2):
        dimension = outputs[0]['shape'][1]
        if type(dimension) is int:
            key = {512: MODEL_KEY, 768: 'vti-l-p14-visual'}.get(dimension)
    vector_present = None if vector_keys is None or key is None else key in vector_keys
    supported = key == MODEL_KEY and vector_present is not False
    reasons = []
    if key is None:
        reasons.append('Runtime interface does not match a recovered native visual configuration')
    elif key != MODEL_KEY:
        reasons.append('L14 inference is unvalidated: the recovered signed model and vector components contain B32 only')
    if vector_present is False:
        reasons.append('Reference-vector JSON does not contain the model-specific tensor key')
    return {
        'interface_model_key': key, 'interface_recognized': key is not None,
        'matches_researched_model_bytes': model_sha256 == KNOWN_MODEL_SHA256,
        'interface_is_identity_proof': False, 'reference_vectors_present': vector_present,
        'adapter_supported': supported, 'unsupported_reasons': reasons,
        'native_default': {'enum': 1, 'name': 'kClipVtiBP32', 'model_key': MODEL_KEY},
        'alternate_native_configuration': {
            'enum': 2, 'name': 'kClipVtiLP14', 'model_key': 'vti-l-p14-visual',
            'native_filename': 'vti-l-p14-visual.quant.ort',
            'input_shape': [1, 3, 224, 224], 'output_shape': [1, 768],
            'asset_status': 'Absent from the recovered authenticated component versions',
            'component_updater_registered_for_this_enum': False,
            'runtime_validated': False,
        },
        'evidence': {'edge_version': '158.0.4370.33', 'configuration_function': '0x189675a98',
                     'model_selector': '0x183c2d83c', 'installer_validation': '0x189663690',
                     'component_registration': '0x189663758 (requires model enum 1)',
                     'filename_selector': '0x188d6b938',
                     'installer_required_filename': 'vti-b-p32-visual.quant.ort'},
    }


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _runtime():
    try:
        import numpy as np
        import onnxruntime as ort
    except ImportError as error:
        raise ValueError('Image inference needs the optional dependencies: '
                         'python -m pip install -r requirements-vision.txt') from error
    ort.disable_telemetry_events()
    return np, ort


def _session(model, threads=1):
    if type(threads) is not int or not 1 <= threads <= 64:
        raise ValueError('threads must be an integer from 1 to 64')
    _, ort = _runtime()
    options = ort.SessionOptions()
    options.intra_op_num_threads = threads
    options.inter_op_num_threads = 1
    try:
        return ort.InferenceSession(str(model), sess_options=options,
                                    providers=['CPUExecutionProvider'])
    except Exception as error:
        raise ValueError('Cannot load the local vision model: ' + str(error)) from error


def _session_description(session):
    def tensors(items):
        return [{'name': x.name, 'shape': x.shape, 'type': x.type} for x in items]
    return {'inputs': tensors(session.get_inputs()), 'outputs': tensors(session.get_outputs()),
            'providers': session.get_providers()}


def inspect_vision(model, vectors=None):
    """Inspect the actual local runtime interface and optional vector structure."""
    model = Path(model)
    session = _session(model)
    _, ort = _runtime()
    result = {'kind': 'scareware_vision_model', 'path': str(model),
              'size': model.stat().st_size, 'sha256': file_sha256(model),
              'runtime_version': ort.__version__, **_session_description(session)}
    result['matches_researched_model'] = result['sha256'] == KNOWN_MODEL_SHA256
    keys = None
    if vectors is not None:
        path = Path(vectors)
        document = _read_vectors(path)
        keys = sorted(document.get('tensors', document))
        result['vectors'] = {'path': str(path), 'size': path.stat().st_size,
                             'sha256': file_sha256(path),
                             'model_keys': keys}
    result['native_compatibility'] = vision_compatibility(
        result, model_sha256=result['sha256'], vector_keys=keys)
    return result


def _read_vectors(path):
    path = Path(path)
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError('Reference-vector JSON exceeds the 64 MiB input limit')
    def invalid_constant(value):
        raise ValueError('Non-finite JSON number: ' + value)
    document = json.loads(path.read_text(encoding='utf-8-sig'), parse_constant=invalid_constant)
    if not isinstance(document, dict):
        raise ValueError('Reference-vector JSON must contain an object')
    return document


class ScarewareClassifier:
    """Load once, then score any number of local screenshots or PIL images."""

    def __init__(self, model, vectors, *, scaling='ShortEdge',
                 resize_method='resize_lanczos3', default_score='knn',
                 default_threshold=80, near_match_boost=True, selected_set_index=0,
                 threads=1):
        self.model = Path(model)
        self.vectors = Path(vectors)
        self.bundle_manifest = None
        self.vector_document = _read_vectors(self.vectors)
        self.model_sha256 = file_sha256(self.model)
        self.vector_sha256 = file_sha256(self.vectors)
        self.session = _session(self.model, threads)
        self.description = _session_description(self.session)
        inputs, outputs = self.session.get_inputs(), self.session.get_outputs()
        if (len(inputs) != 1 or inputs[0].name != 'input' or
                inputs[0].type != 'tensor(float)' or len(inputs[0].shape) != 4 or
                inputs[0].shape[1:] != [3, 224, 224] or
                len(outputs) != 1 or outputs[0].name != 'output' or
                outputs[0].type != 'tensor(float)' or len(outputs[0].shape) != 2 or
                outputs[0].shape[1] != 512):
            raise ValueError('This adapter supports the researched B32 model: '
                             'float input [batch,3,224,224], output [batch,512]')
        self.scaling = scaling
        self.resize_method = resize_method
        self.scoring_options = {'default_score': default_score,
                                'default_threshold': default_threshold,
                                'near_match_boost': near_match_boost,
                                'selected_set_index': selected_set_index}

    @classmethod
    def from_bundle(cls, directory, **options):
        """Verify a downloaded bundle's signatures and file hashes before loading."""
        from smartscreen.vision_assets import verify_bundle
        root = Path(directory)
        manifest = verify_bundle(root, verify_signatures=True)
        classifier = cls(root / manifest['paths']['model'], root / manifest['paths']['vectors'],
                         **options)
        classifier.bundle_manifest = manifest
        return classifier

    def score_image(self, image, *, include_embedding=False):
        """Return local visual scores, reference matches and provenance as JSON data."""
        from smartscreen.vision_image import prepare_image
        from smartscreen.vision_scoring import analyze_embedding
        np, ort = _runtime()
        start = time.monotonic()
        tensor, preprocessing = prepare_image(image, scaling=self.scaling,
                                               resize_method=self.resize_method)
        if tensor.dtype != np.float32 or tensor.shape != (1, 3, 224, 224):
            raise ValueError('Preprocessing did not produce the supported float32 input shape')
        try:
            output = self.session.run(['output'], {'input': tensor})[0]
        except Exception as error:
            raise ValueError('Local vision inference failed: ' + str(error)) from error
        if output.shape != (1, 512) or not np.isfinite(output).all():
            raise ValueError('Model output must be a finite [1,512] embedding')
        scores = analyze_embedding(output[0].tolist(), self.vector_document,
                                   model_key=MODEL_KEY,
                                   image_size=tuple(preprocessing['source_size']),
                                   include_embedding=include_embedding,
                                   **self.scoring_options)
        return {'kind': 'local_scareware_image_analysis', 'model_key': MODEL_KEY,
                'model': {'path': str(self.model), 'sha256': self.model_sha256,
                          'matches_researched_model': self.model_sha256 == KNOWN_MODEL_SHA256},
                'vectors': {'path': str(self.vectors), 'sha256': self.vector_sha256},
                'runtime': {'name': 'onnxruntime', 'version': ort.__version__,
                            'providers': self.session.get_providers()},
                'preprocessing': preprocessing, 'analysis': scores,
                'elapsed_seconds': round(time.monotonic() - start, 6),
                'cloud_verdict': None, 'browser_decision': None,
                'scope': 'Local image-model result; browser triggers, allowlists, policy and cloud reputation are separate.'}


def score_image(image, *, model, vectors, **options):
    """One-shot Python interface; reuse ScarewareClassifier for multiple images."""
    include_embedding = options.pop('include_embedding', False)
    return ScarewareClassifier(model, vectors, **options).score_image(
        image, include_embedding=include_embedding)
