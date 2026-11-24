#!/usr/bin/env python3
"""Run saved scam/not-scam image controls locally, with explicit artifact drift."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smartscreen.vision import ScarewareClassifier, file_sha256

DEFAULT_FIXTURES = Path(__file__).resolve().parents[1] / 'tests/fixtures/vision'


def _fixture(root, relative):
    if not isinstance(relative, str) or Path(relative).is_absolute():
        raise ValueError('Fixture paths must be relative')
    path = (root / relative).resolve()
    if root not in path.parents or not path.is_file():
        raise ValueError('Fixture is missing or outside its directory')
    return path


def validate(assets, fixtures=DEFAULT_FIXTURES, *, require_baseline=False):
    root = Path(fixtures).resolve()
    manifest_path = root / 'fixtures.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if (not isinstance(manifest, dict) or manifest.get('schema_version') != 1 or
            not isinstance(manifest.get('cases'), list) or not 1 <= len(manifest['cases']) <= 1000):
        raise ValueError('Unsupported or empty fixture manifest')
    paths = []
    for case in manifest['cases']:
        if not isinstance(case, dict) or case.get('expected_classification') not in ('scam', 'not_scam'):
            raise ValueError('Invalid fixture case')
        path = _fixture(root, case.get('file'))
        if file_sha256(path) != case.get('sha256'):
            raise ValueError('Fixture hash mismatch: ' + str(path))
        preparation = case.get('preparation', {})
        if 'source_file' in preparation:
            source = _fixture(root, preparation['source_file'])
            if file_sha256(source) != preparation.get('source_sha256'):
                raise ValueError('Fixture source hash mismatch: ' + str(source))
        paths.append(path)
    selected = manifest.get('selected_set_index', 0)
    classifier = ScarewareClassifier.from_bundle(assets,
        scaling=manifest.get('scaling', 'ShortEdge'),
        resize_method=manifest.get('resize_method', 'resize_lanczos3'),
        selected_set_index=selected)
    current = classifier.bundle_manifest
    baseline = manifest.get('baseline_assets', {})
    asset_match = current['sha256'] == baseline.get('sha256')
    results = []
    runtime = None
    for case, path in zip(manifest['cases'], paths):
        result = classifier.score_image(path)
        runtime = result['runtime']
        analysis = result['analysis']
        tensor_set = analysis['tensor_sets'][selected]
        mode = tensor_set['selected_score']
        scores = [pool['scores'].get(mode, {}).get('score') for pool in tensor_set['pools']]
        thresholds = [pool['threshold'] for pool in tensor_set['pools']]
        passed = analysis['classification'] == case['expected_classification']
        results.append({'file': case['file'], 'sha256': case['sha256'], 'passed': passed,
                        'expected_classification': case['expected_classification'],
                        'classification': analysis['classification'],
                        'selected_set_index': selected, 'selected_score': mode,
                        'pool_scores': scores, 'thresholds': thresholds,
                        'baseline_scores_match': scores == case.get('expected_pool_scores'),
                        'baseline_thresholds_match': thresholds == case.get('thresholds'),
                        'elapsed_seconds': result['elapsed_seconds'],
                        'preprocessing': result['preprocessing']})
    return {'schema_version': 1, 'operation': 'offline_image_regression_controls',
            'collected_utc': datetime.now(timezone.utc).isoformat(),
            'passed': all(row['passed'] for row in results) and (asset_match or not require_baseline),
            'baseline_assets_match': asset_match, 'require_baseline': require_baseline,
            'assets_sha256': current['sha256'],
            'asset_versions': {key: value['version'] for key, value in current['components'].items()},
            'fixture_manifest_sha256': file_sha256(manifest_path),
            'results': results, 'runtime': runtime, 'network_requests': 0,
            'scope': 'Two preserved image controls, not a detection-accuracy benchmark or browser enforcement test.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets', type=Path, default=Path('models/scareware'))
    parser.add_argument('--fixtures', type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument('--require-baseline', action='store_true', help='Also fail if any signed asset differs from the saved baseline')
    parser.add_argument('-o', '--output', type=Path)
    args = parser.parse_args()
    try:
        if args.output:
            target = args.output.resolve()
            for root in (args.assets.resolve(), args.fixtures.resolve()):
                if target == root or root in target.parents:
                    raise ValueError('Save validation reports outside asset and fixture directories')
                if args.output.exists() and root.is_dir():
                    if any(path.is_file() and args.output.samefile(path) for path in root.rglob('*')):
                        raise ValueError('Validation output must not alias an asset or fixture')
        result = validate(args.assets, args.fixtures, require_baseline=args.require_baseline)
        encoded = json.dumps(result, indent=2, allow_nan=False) + '\n'
        if args.output:
            args.output.write_text(encoded, encoding='utf-8')
        else:
            print(encoded, end='')
        return 0 if result['passed'] else 1
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        parser.exit(2, str(error) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
