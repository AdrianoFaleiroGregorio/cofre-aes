"""Executa o roteiro de verificação (Etapa 6) contra a API real e o Supabase.

Pré-requisitos: .env configurado e servidor em execução
(uvicorn app.main:app). A adulteração dos Testes 4 e 5 é feita com o
cliente do Supabase — o mesmo acesso que um invasor com a chave pública teria.

Execução, a partir da raiz do projeto:
    python -m testes.roteiro_supabase
"""

import json

import httpx

from app.banco import supabase

API = "http://127.0.0.1:8000"
SENHA_MESTRA = "eq07-cofre-2026"
SENHA_PROTEGIDA = "S3nh@-do-Banco!"
CAB = {"X-Senha-Mestra": SENHA_MESTRA}

http = httpx.Client(base_url=API, timeout=30)


def titulo(texto):
    print("\n" + "=" * 72 + "\n" + texto + "\n" + "=" * 72)


def mostrar(resposta):
    print(f"{resposta.request.method} {resposta.request.url.path}"
          f"  ->  HTTP {resposta.status_code}")
    print(json.dumps(resposta.json(), ensure_ascii=False, indent=2))


def tabela(linhas, colunas):
    for linha in linhas:
        print("  " + " | ".join(f"{c}={linha[c]}" for c in colunas))


def resultado(ok):
    print("RESULTADO:", "APROVADO" if ok else "REPROVADO")
    return ok


# ---------------------------------------------------------------------------
titulo("Preparação")
r = http.post("/cofres", json={"nome": "Equipe 07", "senha_mestra": SENHA_MESTRA})
mostrar(r)
cofre = r.json()["id"]
base = f"/cofres/{cofre}/segredos"

r = http.post(f"/cofres/{cofre}/abrir", headers=CAB)
mostrar(r)

r = http.post(base, headers=CAB, json={"titulo": "Banco produção", "usuario": "admin",
                                       "url": "db-prod.interno", "senha": SENHA_PROTEGIDA})
mostrar(r)
seg_a = r.json()["id"]
r = http.post(base, headers=CAB, json={"titulo": "Banco testes", "usuario": "admin",
                                       "url": "db-test.interno", "senha": SENHA_PROTEGIDA})
mostrar(r)
seg_b = r.json()["id"]

mostrar(http.get(base, headers=CAB))
mostrar(http.get(f"{base}/{seg_a}", headers=CAB))

aprovados = []

# ---------------------------------------------------------------------------
titulo("Teste 1 — Nonces distintos")
linhas = (supabase.table("segredos").select("id, titulo, nonce, criptograma")
          .eq("cofre_id", cofre).order("criado_em").execute().data)
tabela(linhas, ("titulo", "nonce", "criptograma"))
aprovados.append(resultado(
    linhas[0]["nonce"] != linhas[1]["nonce"]
    and linhas[0]["criptograma"] != linhas[1]["criptograma"]))

# ---------------------------------------------------------------------------
titulo("Teste 2 — Senha-mestra incorreta")
r = http.get(f"{base}/{seg_a}", headers={"X-Senha-Mestra": "senha-errada"})
mostrar(r)
aprovados.append(resultado(r.status_code == 401 and SENHA_PROTEGIDA not in r.text))

# ---------------------------------------------------------------------------
titulo("Teste 3 — O que o invasor enxerga")
print("select titulo, usuario, nonce, criptograma, etiqueta from public.segredos;")
linhas = (supabase.table("segredos")
          .select("titulo, usuario, nonce, criptograma, etiqueta").execute().data)
tabela(linhas, ("titulo", "usuario", "nonce", "criptograma", "etiqueta"))
aprovados.append(resultado(SENHA_PROTEGIDA not in json.dumps(linhas)))

# ---------------------------------------------------------------------------
titulo("Teste 4 — Registro adulterado")
original = (supabase.table("segredos").select("criptograma")
            .eq("id", seg_a).execute().data[0]["criptograma"])
adulterado = ("X" if original[0] != "X" else "Y") + original[1:]
supabase.table("segredos").update({"criptograma": adulterado}).eq("id", seg_a).execute()
print(f"criptograma: {original}  ->  {adulterado}")
r = http.get(f"{base}/{seg_a}", headers=CAB)
mostrar(r)
aprovados.append(resultado(r.status_code == 500 and SENHA_PROTEGIDA not in r.text))
supabase.table("segredos").update({"criptograma": original}).eq("id", seg_a).execute()
print("(criptograma original restaurado)")

# ---------------------------------------------------------------------------
titulo("Teste 5 — Troca de criptogramas entre registros")
campos = (supabase.table("segredos").select("nonce, criptograma, etiqueta")
          .eq("id", seg_a).execute().data[0])
originais_b = (supabase.table("segredos").select("nonce, criptograma, etiqueta")
               .eq("id", seg_b).execute().data[0])
supabase.table("segredos").update(campos).eq("id", seg_b).execute()
print(f"nonce/criptograma/etiqueta copiados de {seg_a} (A) para {seg_b} (B)")
print("controle — leitura de A:")
r_a = http.get(f"{base}/{seg_a}", headers=CAB)
mostrar(r_a)
print("leitura de B:")
r = http.get(f"{base}/{seg_b}", headers=CAB)
mostrar(r)
aprovados.append(resultado(r_a.status_code == 200 and r.status_code == 500
                           and SENHA_PROTEGIDA not in r.text))
supabase.table("segredos").update(originais_b).eq("id", seg_b).execute()
print("(campos originais de B restaurados)")

# ---------------------------------------------------------------------------
titulo("Resumo")
for i, ok in enumerate(aprovados, 1):
    print(f"Teste {i}: {'APROVADO' if ok else 'REPROVADO'}")
print(f"\ncofre de teste: {cofre}\nsegredo A: {seg_a}\nsegredo B: {seg_b}")
