#!/usr/bin/env python3
"""Compara formatos sintéticos con gitleaks del PATH, sin red ni llaves reales.

Uso desde cualquier directorio: python3 scripts/cobertura_secretos.py
La salida es Markdown. Los cuerpos repetitivos son deliberadamente falsos;
las reglas de entropía de gitleaks pueden rechazarlos. No mide validez.
"""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from garita.detectores import secretos


def muestras():
    """Proveedor, forma, valor falso, negativo de longitud/alfabeto incorrecto."""
    hex32 = 'a1b2c3d4' * 4
    alfa = 'AbCdEfGh'
    casos = []

    def agregar(proveedor, tipo, prefijo, cuerpo, minimo=None):
        valor = prefijo + cuerpo
        negativo = prefijo + cuerpo[:minimo - 1] if minimo else valor[:-1]
        casos.append((proveedor, tipo, valor, negativo))

    for prefijo in ('ASIA', 'ABIA', 'ACCA', 'A3TA', 'A3T9'):
        agregar('AWS', prefijo, prefijo, 'ABCD2345' * 2)
    agregar('Azure', 'AD client secret', 'Ab_8Q~', 'Ab9_~.-' * 4 + 'Ab9', 31)
    agregar('Azure', 'Storage AccountKey', 'AccountKey=', 'Ab9/' * 21 + 'Ab==')
    agregar('Azure', 'Service Bus SharedAccessKey', 'SharedAccessKey=', 'Ab9/' * 10 + 'Ab9=')
    casos.append(('Slack', 'app token', 'xapp-' + '1-ABCD2345-123456-abc123',
                  'xapp-' + '1-ABCD2345-id-abc123'))
    for tipo in ('services', 'workflows', 'triggers'):
        agregar('Slack', tipo, 'https://hooks.slack.com/' + tipo + '/',
                'T234ABCD/B234ABCD/' + 'AbCd2345' * 4, 43)
    agregar('Twilio', 'API key', 'SK', hex32)
    agregar('SendGrid', 'API key', 'SG.', 'AbCd_9-' * 3 + 'A.' + 'AbCd_9-' * 6 + 'A')
    agregar('Supabase', 'access token', 'sbp_', hex32 + 'a1b2c3d4')
    for prefijo in ('doo', 'dop', 'dor'):
        agregar('DigitalOcean', prefijo, prefijo + '_v1_', hex32 * 2)
    for prefijo in ('shpat_', 'shpca_', 'shppa_', 'shpss_'):
        agregar('Shopify', prefijo, prefijo, hex32)
    agregar('PyPI', 'upload token', 'pypi-' + 'AgEIcHlwaS5vcmc', 'Ab9_' * 13, 50)
    agregar('Hugging Face', 'access token', 'hf_', alfa * 4 + 'Ab')
    agregar('Vault', 'service token', 'hvs.', 'Ab9_' * 24, 90)
    agregar('age', 'private key', 'AGE-SECRET-KEY-' + '1', 'QPZRY9X8' * 7 + 'GF')
    agregar('Databricks', 'API token', 'dapi', hex32)
    casos.append(('Databricks', 'API token suffix', 'dapi' + hex32 + '-1',
                  'dapi' + hex32 + '-12'))
    agregar('Doppler', 'personal token', 'dp.pt.', 'Ab9' * 14 + 'A')
    agregar('Linear', 'API key', 'lin_api_', 'Ab9C' * 10)
    agregar('Notion', 'API token', 'ntn_', '12345678901' + 'Ab9C' * 8 + 'Ab9')
    agregar('Postman', 'API token', 'PMAK-', 'a1b2c3' * 4 + '-' + hex32 + 'a1')
    agregar('Pulumi', 'API token', 'pul-', hex32 + 'a1b2c3d4')
    agregar('Sentry', 'user token', 'sntryu_', hex32 * 2)
    agregar('Grafana', 'service account', 'glsa_', 'Ab9C' * 8 + '_' + 'a1b2c3d4')
    for prefijo in ('tkn', 'pw', 'oauth'):
        agregar('PlanetScale', prefijo, 'pscale_' + prefijo + '_', 'Ab9=' * 8)
    for prefijo in ('gldt-', 'glrt-'):
        agregar('GitLab', prefijo, prefijo, 'Ab9_' * 5)
    agregar('GitLab', 'pipeline trigger', 'glptt-', hex32 + 'a1b2c3d4')
    agregar('GitLab', 'routable runner', 'glrt-' + 't1_', 'Ab9_' * 7 + '.ab1234567')
    agregar('Heroku', 'API key v2', 'HRKU-AA', 'Ab9_' * 14 + 'Ab')
    return casos


def referencias():
    """Cobertura previa y límites sin firma, además de los formatos del issue."""
    import base64
    alfabeto = 'AbCdEfGhIjKlMnOpQrStUvWxYz23456789'

    def cuerpo(n):
        return (alfabeto * (n // len(alfabeto) + 1))[:n]

    casos = []
    for proveedor, prefijo, n in (
            ('AWS', 'AKIA', 16), ('Google', 'AIza', 35),
            ('GitHub', 'ghp_', 36), ('GitHub', 'gho_', 36),
            ('GitHub', 'ghs_', 36), ('GitHub', 'github_pat_', 82),
            ('Slack', 'xoxb-', 40), ('Slack', 'xoxp-', 40),
            ('Stripe', 'sk_live_', 24), ('Stripe', 'rk_live_', 24),
            ('OpenAI', 'sk-proj-', 120), ('OpenAI', 'sk-', 48),
            ('Anthropic', 'sk-ant-api03-', 95),
            ('Anthropic', 'sk-ant-admin01-', 95),
            ('Supabase', 'sb_secret_', 32), ('npm', 'npm_', 36)):
        # Referencias de cobertura previa; no son controles negativos.
        valor = prefijo + cuerpo(n)
        if proveedor == 'AWS':
            valor = prefijo + 'ABCD2345' * 2
        elif prefijo in ('xoxb-', 'xoxp-'):
            valor = prefijo + '123456789012-' + '234567890123-' + cuerpo(24)
        casos.append((proveedor, prefijo, valor))
    for etiqueta in ('RSA', 'OPENSSH', 'EC'):
        casos.append(('PEM', etiqueta, '-----BEGIN ' + etiqueta +
                      ' PRIVATE KEY-----\n' + cuerpo(64) + '\n-----END ' +
                      etiqueta + ' PRIVATE KEY-----'))
    for esquema, usuario in (('postgres', 'app'), ('redis', ''), ('https', 'deploy')):
        casos.append(('URL', esquema, esquema + '://' + usuario + ':' + cuerpo(24)
                      + '@servidor.interno/recurso'))
    def segmento(objeto):
        return base64.urlsafe_b64encode(json.dumps(objeto).encode()).decode().rstrip('=')
    casos.append(('Supabase', 'service role JWT', segmento({'alg': 'HS256', 'typ': 'JWT'})
                  + '.' + segmento({'iss': 'supabase', 'role': 'service_role'})
                  + '.' + cuerpo(43)))
    casos.extend((('AWS', 'secret sin firma', cuerpo(40)),
                  ('Twilio', 'auth sin firma', 'a1b2c3d4' * 4)))
    return casos


def contextos(valor, variable="valor"):
    yield 'suelta', 'INFO recibido ' + valor + ' fin\n'
    yield 'asignada', variable + ' = "' + valor + '"\n'


def detectar(texto, nombre):
    return sorted({h.detector for h in list(secretos.buscar(texto, nombre))
                   + list(secretos.buscar_asignaciones(texto, nombre))})


def main():
    ejecutable = shutil.which('gitleaks')
    if not ejecutable:
        print('No se encontró gitleaks en el PATH; instala gitleaks y regenera la tabla.',
              file=sys.stderr)
        return 2
    filas = []
    with tempfile.TemporaryDirectory(prefix='garita-cobertura-') as temporal:
        raiz = Path(temporal)
        entradas = raiz / 'muestras'
        entradas.mkdir()
        for proveedor, tipo, valor, negativo in muestras():
            for clase, muestra in (('positivo', valor), ('negativo', negativo)):
                for contexto, texto in contextos(muestra):
                    nombre = 'm{:03d}.txt'.format(len(filas))
                    (entradas / nombre).write_text(texto, encoding='utf-8')
                    filas.append((proveedor, tipo + ' (' + clase + ')', contexto,
                                  nombre, detectar(texto, nombre)))
        for proveedor, tipo, valor in referencias():
            for contexto, texto in contextos(valor, 'API_KEY'):
                nombre = 'm{:03d}.txt'.format(len(filas))
                (entradas / nombre).write_text(texto, encoding='utf-8')
                filas.append((proveedor, tipo + ' (referencia)', contexto,
                              nombre, detectar(texto, nombre)))
        for tipo, valor in (('hash hex', 'a1b2c3d4' * 8),
                            ('UUID', '3f2b8c1e-9d4a-4f6b-8e2a-1c7d5e9b0a42'),
                            ('base64', 'Ab9/' * 22),
                            ('SKU', 'SKU-SK' + '01234567'),
                            ('documentación AWS', 'AKIA' + 'IOSFODNN7EXAMPLE')):
            for contexto, texto in contextos(valor):
                nombre = 'm{:03d}.txt'.format(len(filas))
                (entradas / nombre).write_text(texto, encoding='utf-8')
                filas.append(('Negativo', tipo, contexto, nombre, detectar(texto, nombre)))
        reporte = raiz / 'reporte.json'
        resultado = subprocess.run(
            [ejecutable, 'dir', str(entradas), '--no-banner', '--report-format', 'json',
             '--report-path', str(reporte), '--exit-code', '0'],
            capture_output=True, text=True)
        if resultado.returncode:
            print('Falló gitleaks: ' + resultado.stderr, file=sys.stderr)
            return resultado.returncode
        hallazgos = json.loads(reporte.read_text(encoding='utf-8') or '[]')
        vistos = {}
        for hallazgo in hallazgos:
            vistos.setdefault(Path(hallazgo['File']).name, set()).add(hallazgo['RuleID'])
    print('| Proveedor | Tipo | Contexto | gitleaks | Garita |')
    print('| --- | --- | --- | --- | --- |')
    for proveedor, tipo, contexto, nombre, garita in filas:
        print('| {} | {} | {} | {} | {} |'.format(
            proveedor, tipo, contexto, ', '.join(sorted(vistos.get(nombre, ()))) or '—',
            ', '.join(garita) or '—'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
