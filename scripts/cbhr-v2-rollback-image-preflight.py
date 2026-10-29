#!/usr/bin/env python3
"""Read-only pre-release check: current Compose chain, image tags and digests."""
import json
import subprocess
from pathlib import Path

BASE = Path('/opt/cbhr-ai/LibreChat')
ADMIN = Path('/opt/cbhr-ai/admin')
MANIFEST = Path('/opt/cbhr-ai/backups/v2-current-rollback-baseline-20261028T205916Z/running-images.tsv')
API_CHAIN = [BASE/'docker-compose.yml', BASE/'docker-compose.override.yml',
             Path('/opt/cbhr-ai/pr35-live-api-only.override.yml'),
             Path('/tmp/cbhr-g2-project-canary.override.yml')]
BRIDGE_CHAIN = API_CHAIN[:3]
CODEAPI_CHAIN = [*API_CHAIN[:2], Path('/opt/cbhr-ai/retention-rc-preview.override.yml')]
ADMIN_CHAIN = [ADMIN/'docker-compose.yml']
TARGETS = {
 'LibreChat': ('api', API_CHAIN, BASE),
 'aibridge': ('aibridge', BRIDGE_CHAIN, BASE),
 'codeapi': ('codeapi', CODEAPI_CHAIN, BASE),
 'cbhr-admin': ('cbhr-admin', ADMIN_CHAIN, ADMIN),
 'cbhr-broker': ('cbhr-broker', ADMIN_CHAIN, ADMIN),
 'chat-mongodb': ('mongodb', API_CHAIN, BASE),
}

def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE).strip()

def composed_document(chain, root):
    for path in chain:
        if not path.is_file():
            raise RuntimeError(f'Missing active Compose input: {path}')
    argv = ['docker','compose','--project-directory',str(root)]
    for path in chain:
        argv.extend(['-f', str(path)])
    argv.extend(['config', '--format', 'json'])
    config = json.loads(run(*argv))
    return config

def composed_service(service, chain, root):
    return composed_document(chain, root)['services'][service]['image']

def main():
    if not MANIFEST.is_file():
        raise RuntimeError('Current deployment baseline manifest is absent')
    manifest = {}
    for line in MANIFEST.read_text().splitlines():
        name, image, digest = line.split('\t')
        manifest[name] = (image, digest)
    expected_names = {'LibreChat','aibridge','codeapi','cbhr-admin','cbhr-broker'}
    if set(manifest) != expected_names:
        raise RuntimeError('Baseline service inventory incomplete')
    for container,(service,chain,root) in TARGETS.items():
        compose_image = composed_service(service,chain,root)
        live_image,live_digest = run('docker','inspect',container,
            '--format','{{.Config.Image}} {{.Image}}').split()
        image_digest = run('docker','image','inspect',compose_image,
            '--format','{{.Id}}')
        if compose_image != live_image or image_digest != live_digest:
            raise RuntimeError(f'{container}: rendered/running image or digest mismatch')
        if container != 'chat-mongodb':
            if manifest[container] != (live_image, live_digest):
                raise RuntimeError(f'{container}: captured rollback baseline differs')
            live_files = run('docker','inspect',container,'--format',
                '{{index .Config.Labels "com.docker.compose.project.config_files"}}')
            if live_files != ','.join(map(str,chain)):
                raise RuntimeError(f'{container}: runtime Compose source chain differs')
        elif compose_image != 'mongo:7.0':
            raise RuntimeError('Mongo 7.0 runtime pin changed')
        print(f'PASS {container}: {compose_image} {live_digest[:19]}')
    fallback = Path(__file__).with_name('cbhr-v2-current-baseline-api-image.override.yml')
    fallback_chain = [*API_CHAIN[:-1], fallback]
    if composed_document(API_CHAIN, BASE) != composed_document(fallback_chain, BASE):
        raise RuntimeError('Version-controlled baseline API image override is not Compose-equivalent')
    print('PASS image-only fallback: exact 11-service Compose config equivalence')
    print('CBHR_V2_CURRENT_ROLLBACK_IMAGE_PREFLIGHT_PASS')
    print('READ_ONLY: no deploy, rollback, database change, or file mutation')

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, RuntimeError) as error:
        print(f'ROLLBACK_PREFLIGHT_BLOCKED: {error}')
        raise SystemExit(1)
