import re, sys

HEX = re.compile(r'^\s*[io]\s+[0-9A-F]{4}((?:\s+[0-9A-F]{2})+)')

def parse(caminho):
    trocas, env, rec, alvo = [], [], [], None
    for l in open(caminho):
        if 'SCardTransmit' in l:
            if env: trocas.append((env, rec))
            env, rec, alvo = [], [], None
        elif 'bSendBuffer' in l: alvo = env
        elif 'bRecvBuffer' in l: alvo = rec
        elif alvo is not None:
            m = HEX.match(l)
            if m: alvo.extend(m.group(1).split())
            elif l.startswith(' =>'): alvo = None
    if env: trocas.append((env, rec))
    return [(e, r) for e, r in trocas if e]

def descreve(a):
    if len(a) < 4: return ''
    cla, ins, p1, p2 = a[:4]
    nomes = {'A4': 'SELECT', 'B0': 'READ BINARY', 'C0': 'GET RESPONSE',
             '20': 'VERIFY PIN', '22': 'MSE', '2A': 'PSO', '88': 'INT AUTH',
             '84': 'GET CHALLENGE', 'CA': 'GET DATA', 'B2': 'READ RECORD'}
    if cla == '00' and ins in nomes:
        n = nomes[ins]
        if ins == 'A4':
            p1n = {'00': 'MF/FID', '02': 'EF sob DF', '04': 'AID',
                   '08': 'caminho desde MF', '09': 'caminho desde DF atual'}.get(p1, p1)
            return f'{n} ({p1n})'
        return n
    return 'PROPRIETARIO (CLA=80)' if cla == '80' else ''

if __name__ == '__main__':
    for i, (e, r) in enumerate(parse(sys.argv[1]), 1):
        sw = ' '.join(r[-2:]) if len(r) >= 2 else '??'
        dados = ' '.join(r[:-2])
        print(f"{i:3}. -> {' '.join(e):<52} {descreve(e)}")
        print(f"     <- SW={sw}" + (f"  [{len(r)-2}B] {dados[:46]}" if dados else ''))
