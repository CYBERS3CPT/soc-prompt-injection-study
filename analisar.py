#!/usr/bin/env python3
"""Agrega resultados.jsonl: reclassifica cada resposta com as funções atuais
de medir.py e calcula a taxa de sucesso do ataque com intervalo de Wilson 95%.
Escreve resumo.json (para o artigo) e imprime tabelas."""
import json, math, os, sys, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import medir  # noqa: E402

AQUI = os.path.dirname(os.path.abspath(__file__))

def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (max(0.0, c - h), min(1.0, c + h))

ultimo = {}
for l in open(os.path.join(AQUI, 'resultados.jsonl') if os.path.exists(os.path.join(AQUI, 'resultados.jsonl')) else os.path.join(AQUI, 'data', 'respostas.jsonl')):
    r = json.loads(l)
    r.setdefault('texto', r.get('resposta'))  # data/respostas.jsonl usa 'resposta'
    r.setdefault('custo', r.get('custo_usd', 0))
    if r.get('texto') is None:
        continue
    ultimo[(r['cenario'], r['estado'], r['modelo'], r['tentativa'])] = r

aval = {c: v[1] for c, v in medir.CENARIOS.items()}
cel = collections.defaultdict(collections.Counter)
custo = 0.0
for (c, e, m, t), r in ultimo.items():
    if m not in medir.MODELOS:
        continue  # modelos retirados da medição (ex.: mistral-small-2603, sem capacidade no fornecedor)
    cel[(c, e, m)][aval[c](r['texto'])] += 1
    custo += r.get('custo', 0)

def taxa(cnt):
    n = cnt['ataque'] + cnt['resistiu'] + cnt['detetou']  # válidas
    return cnt['ataque'], n

out = {'custo_usd': round(custo, 4), 'respostas': len(ultimo), 'celulas': [], 'por_estado': {}, 'por_cenario_estado': {}, 'por_modelo': {}}
for (c, e, m), cnt in sorted(cel.items()):
    k, n = taxa(cnt)
    lo, hi = wilson(k, n)
    out['celulas'].append({'cenario': c, 'estado': e, 'modelo': m, 'ataque': k, 'validas': n,
                           'detetou': cnt['detetou'], 'invalidas': cnt['invalido'], 'taxa': k / n if n else None,
                           'ic95': [lo, hi]})

def agrega(chave):
    acc = collections.defaultdict(lambda: [0, 0, 0, 0])
    for x in out['celulas']:
        a = acc[chave(x)]
        a[0] += x['ataque']; a[1] += x['validas']; a[2] += x['detetou']; a[3] += x['invalidas']
    return {k: {'ataque': a[0], 'validas': a[1], 'detetou': a[2], 'invalidas': a[3],
                'taxa': a[0] / a[1] if a[1] else None, 'ic95': wilson(a[0], a[1])} for k, a in acc.items()}

out['por_estado'] = agrega(lambda x: x['estado'])
out['por_cenario_estado'] = {f'{k[0]}|{k[1]}': v for k, v in agrega(lambda x: (x['cenario'], x['estado'])).items()}
out['por_modelo'] = {f'{k[0]}|{k[1]}': v for k, v in agrega(lambda x: (x['modelo'], x['estado'])).items()}
json.dump(out, open(os.path.join(AQUI, 'data', 'resumo-detalhado.json'), 'w'), ensure_ascii=False, indent=1)

pct = lambda v: '  n/d ' if not v or v['taxa'] is None else f"{100*v['taxa']:5.1f}%"
print(f"respostas válidas guardadas: {len(ultimo)} · custo {custo:.3f} USD\n")
print('POR ESTADO (todos os modelos e cenários)')
for e in medir.ESTADOS:
    v = out['por_estado'][e]; print(f"  {e:10} {pct(v)}  ({v['ataque']}/{v['validas']}, IC95 {100*v['ic95'][0]:.0f}-{100*v['ic95'][1]:.0f}%, detetou {v['detetou']}, inválidas {v['invalidas']})")
print('\nPOR CENÁRIO x ESTADO')
for c in medir.CENARIOS:
    print('  ' + c.ljust(6) + '  '.join(f"{e}:{pct(out['por_cenario_estado'].get(f'{c}|{e}'))}" for e in medir.ESTADOS))
print('\nPOR MODELO x ESTADO (todos os cenários)')
for m in medir.MODELOS:
    print('  ' + m.split('/')[1][:24].ljust(25) + '  '.join(f"{e}:{pct(out['por_modelo'].get(f'{m}|{e}'))}" for e in medir.ESTADOS))
print('\nCÉLULAS (modelo · cenário · estado)')
for x in out['celulas']:
    if x['estado'] != 'limpo':
        print(f"  {x['modelo'].split('/')[1][:22]:22} {x['cenario']:5} {x['estado']:9} {x['ataque']:2}/{x['validas']:<2} det={x['detetou']:<2} inv={x['invalidas']}")

# ---------------------------------------------------------------- exportação para o site
NOMES = {
    'openai/gpt-4o-mini': ('GPT-4o mini', 'OpenAI'),
    'openai/gpt-5.6-luna': ('GPT-5.6 Luna', 'OpenAI'),
    'anthropic/claude-haiku-5.5': ('Claude Haiku 5.5', 'Anthropic'),
    'google/gemini-3.8-flash': ('Gemini 3.8 Flash', 'Google'),
    'meta-llama/llama-3.3-70b-instruct': ('Llama 3.3 70B', 'Meta, pesos abertos'),
    'mistralai/mistral-small-3.2-24b-instruct': ('Mistral Small 3.2', 'Mistral, pesos abertos'),
}
site = {'data': '2026-10-14', 'tentativas': 20, 'temperatura': medir.TEMPERATURA,
        'modelos': [{'id': m, 'nome': NOMES[m][0], 'origem': NOMES[m][1]} for m in medir.MODELOS],
        'estados': medir.ESTADOS, 'cenarios': ['todos'] + list(medir.CENARIOS), 'celulas': {}}
n_resp = 0
custo_site = 0.0
for (c, e, m, t), r in ultimo.items():
    if m in medir.MODELOS:
        n_resp += 1; custo_site += r.get('custo', 0)
site['respostas'] = n_resp
site['custo_usd'] = round(custo_site, 2)
for cen in site['cenarios']:
    for m in medir.MODELOS:
        for e in medir.ESTADOS:
            k = n = det = inv = 0
            for x in out['celulas']:
                if x['modelo'] == m and x['estado'] == e and (cen == 'todos' or x['cenario'] == cen):
                    k += x['ataque']; n += x['validas']; det += x['detetou']; inv += x['invalidas']
            lo, hi = wilson(k, n)
            site['celulas'][f'{cen}|{m}|{e}'] = {'k': k, 'n': n, 'lo': round(lo, 3), 'hi': round(hi, 3), 'det': det, 'inv': inv}
destino = os.path.join(AQUI, 'data', 'resumo.json')
json.dump(site, open(destino, 'w'), ensure_ascii=False, indent=1)
print(f'\nexportado para o site: {destino} ({n_resp} respostas dos modelos atuais)')
