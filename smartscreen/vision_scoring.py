"""Offline Edge 158 visual-classifier scoring reconstructed from native code.

Inputs are the raw model embedding and the accompanying vector JSON. This
module performs no network requests and does not predict browser enforcement.
Evidence and bounded native arithmetic probes: analysis/scareware_scoring/.
"""
import math
import struct
from numbers import Real

READER = 'edge_158.0.4370.33_arm64'
BINARY_SHA256 = '788fe22e3a1a893f042a8bcdeef0765f0fd39c665d46de4f02c28bc5437f7173'
MODEL_DIMENSIONS = {'vti-b-p32-visual': 512, 'vti-l-p14-visual': 768}
SCORES = ('softmax', 'knn', 'knn2')
NEAR_DISTANCE = 0.009999999776482582
KNN2_DISTANCE = 0.05999999865889549
SUM_TOLERANCE = 9.999999747378752e-05


def f32(value):
    """Round once to IEEE-754 binary32 without requiring NumPy."""
    return struct.unpack('<f', struct.pack('<f', value))[0]


def _values(values, count=None):
    if not isinstance(values, (list, tuple)) or not values or len(values) > 16384:
        raise ValueError('Expected a nonempty bounded numeric vector')
    if count is not None and len(values) != count:
        raise ValueError('Vector dimension does not match the selected model or label pool')
    output = []
    for value in values:
        if isinstance(value, bool) or not isinstance(value, Real):
            raise ValueError('Vector components must be numeric values')
        try:
            converted = f32(float(value))
        except (OverflowError, TypeError, ValueError) as error:
            raise ValueError('Vector component is not finite float32') from error
        if not math.isfinite(converted):
            raise ValueError('Vector component is not finite float32')
        output.append(converted)
    return output


def normalize_embedding(embedding):
    values = _values(list(embedding))
    total = 0.0
    try:
        for value in values:
            total = f32(total + f32(value * value))
    except OverflowError as error:
        raise ValueError('Embedding norm overflows float32') from error
    norm = f32(math.sqrt(total))
    if not math.isfinite(norm) or norm == 0.0:
        raise ValueError('Embedding has zero or nonfinite float32 norm')
    return [f32(value / norm) for value in values]


def _dot(left, right):
    total = 0.0
    try:
        for x, y in zip(left, right):
            total = f32(total + f32(x * y))
    except OverflowError as error:
        raise ValueError('Label dot product overflows float32') from error
    return total


def softmax_probabilities(logits, scale=100.0):
    """Native double exp/sum/division followed by float32 probabilities."""
    logits = _values(list(logits))
    scale = f32(scale)
    try:
        exponentials = [math.exp(float(scale) * value) for value in logits]
    except OverflowError as error:
        raise ValueError('SoftMax exponent overflow') from error
    denominator = 0.0
    for value in exponentials:
        denominator += value
    if not math.isfinite(denominator) or denominator <= 0:
        raise ValueError('Invalid SoftMax denominator')
    probabilities = [f32(value / denominator) for value in exponentials]
    total = 0.0
    for value in probabilities:
        total = f32(total + value)
    if any(not math.isfinite(value) or not 0 <= value <= 1 for value in probabilities) or abs(f32(total - 1.0)) > SUM_TOLERANCE:
        raise ValueError('Native probability validation failed')
    return probabilities


def _distance(left, right):
    total = 0.0
    try:
        for x, y in zip(left, right):
            difference = f32(x - y)
            total = f32(total + f32(difference * difference))
    except OverflowError as error:
        raise ValueError('Reference distance overflows float32') from error
    return f32(math.sqrt(total))


def _additional_match(point, references):
    for row in references:
        total = 0.0
        try:
            for x, y in zip(point, row):
                difference = f32(x - y)
                total += float(f32(difference * difference))
        except OverflowError as error:
            raise ValueError('Additional-reference distance overflows float32') from error
        if math.sqrt(total) <= 0.01000000024214387:
            return True
    return False


def _rows(document, name, dimension):
    values = document.get(name, [])
    if not isinstance(values, list) or len(values) > 100000:
        raise ValueError('Expected a bounded ' + name + ' list')
    return [_values(row, dimension) for row in values]


def knn_scores(probabilities, good_data, scam_data, near_match_boost=True):
    """Return both native neighbor scores; unavailable results remain unknown.

    Distances are sequential float32 Euclidean distances. KNN's unstable native
    equal-distance ordering is not invented: mixed-label ties at the fifth
    neighbor return unknown when they can affect its score.
    """
    point = _values(list(probabilities))
    good = [_distance(point, _values(row, len(point))) for row in good_data]
    scam = sorted(_distance(point, _values(row, len(point))) for row in scam_data)
    result = {name: {'score': None, 'available': False, 'near_match': None} for name in ('knn', 'knn2')}
    if len(scam) < 5:
        for item in result.values(): item['reason'] = 'Fewer than five scam reference vectors'
        return result
    near = bool(near_match_boost and scam[0] <= NEAR_DISTANCE)
    score2 = 100 if near else 20 * sum(value < KNN2_DISTANCE for value in scam[:5])
    result['knn2'] = {'score': score2, 'available': True, 'near_match': near,
                      'nearest_distances': scam[:5]}
    if not good:
        result['knn']['reason'] = 'No benign reference vectors'
    else:
        combined = sorted([(value, False) for value in good] + [(value, True) for value in scam])
        cutoff = combined[4][0]
        tied = [label for value, label in combined if value == cutoff]
        below = [label for value, label in combined if value < cutoff]
        certain_near = bool(near_match_boost and any(label and value <= NEAR_DISTANCE for value, label in combined if value < cutoff))
        mixed_tie = len(tied) > 5 - len(below) and len(set(tied)) > 1
        if mixed_tie and not certain_near:
            result['knn']['reason'] = 'Mixed-label distance tie crosses the fifth-neighbor boundary; native tie order is unvalidated'
        else:
            nearest = combined[:5]
            near1 = certain_near or bool(near_match_boost and any(label and value <= NEAR_DISTANCE for value, label in nearest))
            result['knn'] = {'score': 100 if near1 else 20 * sum(label for _, label in nearest),
                             'available': True, 'near_match': near1,
                             'nearest_distances': [value for value, _ in nearest]}
    if result['knn']['available'] and result['knn2']['available'] and result['knn']['near_match'] != result['knn2']['near_match']:
        for item in result.values():
            item.update({'score': None, 'available': False, 'reason': 'Native KNN/KNN2 near-match consistency check failed'})
    return result


def _select_dataset(knn_data, image_size):
    if not isinstance(knn_data, dict):
        raise ValueError('knn_data must be an object')
    if image_size is None:
        return knn_data, {'kind': 'base', 'reason': 'No original image dimensions supplied'}
    if len(image_size) != 2 or any(type(value) is not int or not 0 < value <= 100000 for value in image_size):
        raise ValueError('image_size must contain two positive bounded integer dimensions')
    resolutions = knn_data.get('resolutions', [])
    if not isinstance(resolutions, list) or len(resolutions) > 4096:
        raise ValueError('knn_data.resolutions must be a bounded list')
    best, chosen = 1000.0, None
    for index, row in enumerate(resolutions):
        if not isinstance(row, dict) or type(row.get('width')) is not int or type(row.get('height')) is not int:
            raise ValueError('Invalid resolution dataset dimensions')
        squared = (image_size[0] - row['width']) ** 2 + (image_size[1] - row['height']) ** 2
        if squared >= 1 << 31:
            raise ValueError('Resolution distance exceeds native signed arithmetic range')
        distance = f32(math.sqrt(f32(squared)))
        if distance < best:
            best, chosen = distance, (index, row)
    if chosen is None:
        return knn_data, {'kind': 'base', 'reason': 'No resolution dataset is strictly within 1000 pixels of the supplied size'}
    return chosen[1], {'kind': 'resolution', 'index': chosen[0], 'width': chosen[1]['width'],
                       'height': chosen[1]['height'], 'distance': best}


def _pool(normalized, pool, image_size, default_threshold, near_match_boost):
    if not isinstance(pool, dict):
        raise ValueError('Label pool must be an object')
    threshold = pool.get('scam_score_threshold', default_threshold)
    if type(threshold) is not int or not 0 <= threshold <= 100:
        raise ValueError('Pool threshold must be an integer from0 through100')
    labels = pool.get('text_tensors')
    if not isinstance(labels, list) or not 1 <= len(labels) <= 4096:
        raise ValueError('Pool must contain a bounded nonempty text_tensors list')
    logits = []
    for label in labels:
        if not isinstance(label, dict) or not isinstance(label.get('name'), str) or type(label.get('is_scam')) is not bool:
            raise ValueError('Invalid text tensor label')
        logits.append(_dot(normalized, _values(label.get('vector'), len(normalized))))
    probabilities = softmax_probabilities(logits)
    scam_probability = 0.0
    for label, value in zip(labels, probabilities):
        if label['is_scam']: scam_probability = f32(scam_probability + value)
    score = int(f32(scam_probability * 100.0))
    output = {'original_labels': pool.get('original_labels', False), 'threshold': threshold,
              'labels': [{'name': label['name'], 'is_scam': label['is_scam'], 'probability': value, 'logit': logit}
                         for label, value, logit in zip(labels, probabilities, logits)],
              'scores': {'softmax': {'score': score if 0 <= score <= 100 else None,
                                     'available': 0 <= score <= 100}},
              'reference_match': None}
    if 'knn_data' in pool:
        dataset, selection = _select_dataset(pool['knn_data'], image_size)
        good = _rows(dataset, 'good_data', len(labels)); scam = _rows(dataset, 'scam_data', len(labels))
        output['dataset_selection'] = selection
        output['scores'].update(knn_scores(probabilities, good, scam, near_match_boost))
        additional = _rows(dataset, 'additional_vectors_data', len(labels))
        output['reference_match'] = _additional_match(probabilities, additional)
    return output


def analyze_embedding(embedding, vector_document, model_key='vti-b-p32-visual', *,
                      image_size=None, default_score='knn', default_threshold=80,
                      near_match_boost=True, include_embedding=False, selected_set_index=0):
    """Analyze a RAW model embedding with explicit native profile assumptions.

    image_size is original(width,height), used only for reference-data selection.
    Zero/invalid embeddings and malformed vector data fail explicitly. Scores
    use original native rounding and thresholds; results are model classifications,
    never cloud reputation or proof of a running Edge warning/block.
    """
    if model_key not in MODEL_DIMENSIONS or default_score not in SCORES:
        raise ValueError('Unsupported native model key or score mode')
    if type(default_threshold) is not int or not 0 <= default_threshold <= 100 or type(near_match_boost) is not bool:
        raise ValueError('Invalid profile defaults')
    raw = _values(list(embedding), MODEL_DIMENSIONS[model_key])
    normalized = normalize_embedding(raw)
    tensors = vector_document.get('tensors', vector_document) if isinstance(vector_document, dict) else None
    sets = tensors.get(model_key) if isinstance(tensors, dict) else None
    if not isinstance(sets, list) or not 1 <= len(sets) <= 1024:
        raise ValueError('Vector document has no bounded nonempty list for the selected model key')
    if type(selected_set_index) is not int or not 0 <= selected_set_index < len(sets):
        raise ValueError('Selected tensor-set index is outside the supplied configuration')
    output = {'schema_version': 1, 'operation': 'offline_visual_embedding_scoring',
              'reader': READER, 'reader_binary_sha256': BINARY_SHA256,
              'model_key': model_key, 'embedding_dimension': len(raw), 'tensor_sets': [],
              'profile_assumptions': {'default_score': default_score, 'default_threshold': default_threshold,
                                      'near_match_boost': near_match_boost, 'selected_set_index': selected_set_index,
                                      'runtime_feature_state_verified': False},
              'cloud_verdict': None, 'browser_decision': None, 'network_requests': 0,
              'limits': ['Native profile defaults and supplied vector configuration are used; running-browser feature state is not captured.',
                         'Model classification is separate from browser policy, trigger eligibility, and warning UI.',
                         'SoftMax and KNN2 arithmetic have bounded original ARM64 p-code checks; full image-to-browser parity is not established.',
                         'Python exp follows the platform math library; differences near thresholds remain possible.',
                         'Mixed-label KNN ties that affect the fifth-neighbor cutoff are reported unknown.']}
    for index, tensor_set in enumerate(sets):
        if not isinstance(tensor_set, dict) or type(tensor_set.get('tensor_set_id')) is not int:
            raise ValueError('Tensor set requires integer tensor_set_id')
        pools = tensor_set.get('label_pool', [tensor_set])
        if not isinstance(pools, list) or not 1 <= len(pools) <= 1024:
            raise ValueError('Invalid label_pool list')
        # The native mode gate examines knn_data on the SET, even when its
        # label_pool entries carry their own neighbor datasets.
        mode = str(tensor_set.get('scam_score_to_use', default_score)).lower()
        if 'knn_data' not in tensor_set:
            mode = 'softmax'
        elif mode not in SCORES:
            mode = default_score
        consensus = tensor_set.get('consensus_threshold', 0)
        if type(consensus) is not int or not 0 <= consensus <= (1 << 31) - 1:
            raise ValueError('Invalid consensus_threshold')
        required = consensus or len(pools)
        observed = [_pool(normalized, pool, image_size, default_threshold, near_match_boost) for pool in pools]
        aggregate = {}
        for name in SCORES:
            valid = all(pool['scores'].get(name, {}).get('available', False) for pool in observed)
            positive = sum(pool['scores'].get(name, {}).get('score', -1) >= pool['threshold'] for pool in observed
                           if pool['scores'].get(name, {}).get('score') is not None)
            aggregate[name] = {'classification': ('scam' if positive >= required else 'not_scam') if valid else 'unknown',
                               'native_result': (2 if positive >= required else 1) if valid else None,
                               'positive_pools': positive, 'required_pools': required,
                               'all_scores_available': valid}
        output['tensor_sets'].append({'index': index, 'tensor_set_id': tensor_set['tensor_set_id'],
                                       'selected_score': mode, 'pools': observed, 'consensus': aggregate,
                                       'classification': aggregate[mode]['classification']})
    output['classification'] = output['tensor_sets'][selected_set_index]['classification']
    if include_embedding: output['normalized_embedding'] = normalized
    return output
