import http.client
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from django.core.cache import cache

log = logging.getLogger('scanner.docker_stats')

_PROXY_URL = os.environ.get('DOCKER_PROXY_URL', 'http://docker-proxy:2375')
_PROJECT = os.environ.get('COMPOSE_PROJECT', 'wireghost')
_CACHE_KEY = 'scanner.docker_processes.v1'
_CACHE_TTL = 3

FRIENDLY_NAMES = {
    'api': 'API Server',
    'worker': 'Scan Worker',
    'beat': 'Scheduler',
    'bot': 'Telegram Bot',
    'portal': 'Web Portal',
    'db': 'Database',
    'redis': 'Cache',
    'docker-proxy': 'Docker Proxy',
}


def _parse_host(url):
    url = url.replace('http://', '').replace('https://', '')
    if ':' in url:
        host, port = url.rsplit(':', 1)
        return host, int(port)
    return url, 2375


def _docker_get(path, timeout=5):
    host, port = _parse_host(_PROXY_URL)
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request('GET', path)
        resp = conn.getresponse()
        if resp.status != 200:
            return None
        return json.loads(resp.read())
    finally:
        conn.close()


def _calc_cpu_percent(stats):
    cpu = stats.get('cpu_stats', {})
    pre = stats.get('precpu_stats', {})
    cpu_delta = cpu.get('cpu_usage', {}).get('total_usage', 0) - pre.get('cpu_usage', {}).get('total_usage', 0)
    sys_delta = cpu.get('system_cpu_usage', 0) - pre.get('system_cpu_usage', 0)
    if sys_delta <= 0 or cpu_delta < 0:
        return 0.0
    online = cpu.get('online_cpus') or len(cpu.get('cpu_usage', {}).get('percpu_usage', []) or [1])
    return round((cpu_delta / sys_delta) * online * 100, 1)


def _calc_memory(stats):
    mem = stats.get('memory_stats', {})
    usage = mem.get('usage', 0)
    limit = mem.get('limit', 0)
    mem_stats = mem.get('stats', {})
    cache_bytes = mem_stats.get('cache') or mem_stats.get('inactive_file') or 0
    used = max(0, usage - cache_bytes)
    pct = round(used / limit * 100, 1) if limit > 0 else 0.0
    return {'used': used, 'limit': limit, 'percent': pct}


def _calc_network(stats):
    networks = stats.get('networks', {})
    rx = sum(v.get('rx_bytes', 0) for v in networks.values())
    tx = sum(v.get('tx_bytes', 0) for v in networks.values())
    return {'rx_bytes': rx, 'tx_bytes': tx}


def _fetch_one_stat(container_id):
    return _docker_get(f'/containers/{container_id}/stats?stream=false', timeout=8)


def get_processes():
    cached = cache.get(_CACHE_KEY)
    if cached is not None:
        return cached

    try:
        containers = _docker_get(f'/containers/json?all=true&filters={{"label":["com.docker.compose.project={_PROJECT}"]}}')
    except Exception as exc:
        log.warning('Docker proxy unreachable: %s', exc)
        return {'containers': [], 'available': False, 'error': str(exc), 'ts': int(time.time() * 1000)}

    if containers is None:
        return {'containers': [], 'available': False, 'error': 'Proxy returned non-200', 'ts': int(time.time() * 1000)}

    results = []
    stat_futures = {}

    with ThreadPoolExecutor(max_workers=4) as pool:
        for c in containers:
            cid = c.get('Id', '')
            stat_futures[pool.submit(_fetch_one_stat, cid)] = c

        for future in as_completed(stat_futures):
            c = stat_futures[future]
            cid = c.get('Id', '')
            labels = c.get('Labels', {})
            service = labels.get('com.docker.compose.service', '')

            try:
                stats = future.result()
            except Exception:
                stats = None

            record = {
                'id': cid[:12],
                'name': FRIENDLY_NAMES.get(service, service or cid[:12]),
                'service': service,
                'image': (c.get('Image') or '').split('@')[0],
                'state': c.get('State', 'unknown'),
                'status': c.get('Status', ''),
                'cpu_percent': 0.0,
                'memory': {'used': 0, 'limit': 0, 'percent': 0.0},
                'network': {'rx_bytes': 0, 'tx_bytes': 0},
                'pids': 0,
            }

            if stats:
                record['cpu_percent'] = _calc_cpu_percent(stats)
                record['memory'] = _calc_memory(stats)
                record['network'] = _calc_network(stats)
                record['pids'] = stats.get('pids_stats', {}).get('current', 0) or 0

            results.append(record)

    results.sort(key=lambda r: r.get('service', ''))

    payload = {
        'containers': results,
        'available': True,
        'ts': int(time.time() * 1000),
    }
    cache.set(_CACHE_KEY, payload, _CACHE_TTL)
    return payload
