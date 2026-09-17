"""Verificação automatizada da API sem Supabase.

Substitui app.banco por uma implementação em memória com a mesma interface e
reproduz os cinco testes da Etapa 6, além de conferir as rotas e os códigos
de resposta. Não substitui as evidências no Supabase — serve para validar o
código antes delas.

Execução, a partir da raiz do projeto:
    python -m testes.teste_local
"""

import copy
import sys
import types
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Banco falso em memória (mesma interface de app/banco.py)
# ---------------------------------------------------------------------------

COFRES: dict[str, dict] = {}
SEGREDOS: dict[str, dict] = {}


def _agora():
    return datetime.now(timezone.utc).isoformat()


def inserir_cofre(cofre_id, nome, sal_b64, iteracoes, verificador):
    n, c, e = verificador
    COFRES[cofre_id] = {
        "id": cofre_id, "nome": nome, "kdf_sal": sal_b64,
        "kdf_iteracoes": iteracoes, "verificador_nonce": n,
        "verificador_criptograma": c, "verificador_etiqueta": e,
        "criado_em": _agora(),
    }


def buscar_cofre(cofre_id):
    return copy.deepcopy(COFRES.get(cofre_id))


def inserir_segredo(segredo_id, cofre_id, titulo, usuario, url, cifrado):
    n, c, e = cifrado
    SEGREDOS[segredo_id] = {
        "id": segredo_id, "cofre_id": cofre_id, "titulo": titulo,
        "usuario": usuario, "url": url, "nonce": n, "criptograma": c,
        "etiqueta": e, "criado_em": _agora(), "atualizado_em": _agora(),
    }


def listar_segredos(cofre_id):
    campos = ("id", "titulo", "usuario", "url", "criado_em", "atualizado_em")
    return [{k: s[k] for k in campos}
            for s in SEGREDOS.values() if s["cofre_id"] == cofre_id]


def buscar_segredo(cofre_id, segredo_id):
    s = SEGREDOS.get(segredo_id)
    return copy.deepcopy(s) if s and s["cofre_id"] == cofre_id else None


def atualizar_segredo(cofre_id, segredo_id, cifrado, metadados, atualizado_em):
    n, c, e = cifrado
    SEGREDOS[segredo_id].update(metadados, nonce=n, criptograma=c,
                                etiqueta=e, atualizado_em=atualizado_em)


def remover_segredo(cofre_id, segredo_id):
    SEGREDOS.pop(segredo_id, None)


banco_falso = types.ModuleType("app.banco")
for _nome in ("inserir_cofre", "buscar_cofre", "inserir_segredo",
              "listar_segredos", "buscar_segredo", "atualizar_segredo",
              "remover_segredo"):
    setattr(banco_falso, _nome, globals()[_nome])
sys.modules["app.banco"] = banco_falso

import app  # noqa: E402
app.banco = banco_falso

from fastapi.testclient import TestClient  # noqa: E402

from app import cripto  # noqa: E402
from app.main import app as api  # noqa: E402

cliente = TestClient(api)
SENHA = "eq07-cofre-2026"
CAB = {"X-Senha-Mestra": SENHA}
falhas = 0


def verificar(descricao, condicao):
    global falhas
    print(("  [OK]   " if condicao else "  [FALHA] ") + descricao)
    if not condicao:
        falhas += 1


# ---------------------------------------------------------------------------
print("Módulo de criptografia")
sal = cripto.gerar_sal()
chave = cripto.derivar_chave(SENHA, sal, cripto.ITERACOES_PADRAO)
verificar("sal de 16 bytes e chave de 32 bytes", len(sal) == 16 and len(chave) == 32)
aad = cripto.montar_aad_segredo("a", "b")
n, c, e = cripto.cifrar(chave, "S3nh@-do-Banco!", aad)
verificar("nonce de 12 bytes, etiqueta de 16, criptograma do tamanho do texto",
          len(cripto.de_b64(n)) == 12 and len(cripto.de_b64(e)) == 16
          and len(cripto.de_b64(c)) == 15)
verificar("ida e volta", cripto.decifrar(chave, n, c, e, aad) == "S3nh@-do-Banco!")
try:
    cripto.decifrar(chave, n, c, e, cripto.montar_aad_segredo("a", "x"))
    verificar("AAD diferente lança ValueError", False)
except ValueError:
    verificar("AAD diferente lança ValueError", True)

# ---------------------------------------------------------------------------
print("Rotas")
r = cliente.post("/cofres", json={"nome": "Equipe 07", "senha_mestra": SENHA})
verificar("POST /cofres -> 201", r.status_code == 201)
cofre_id = r.json()["id"]
verificar("senha-mestra não é armazenada",
          SENHA not in str(COFRES[cofre_id]))

verificar("abrir com senha correta -> 200",
          cliente.post(f"/cofres/{cofre_id}/abrir", headers=CAB).status_code == 200)
verificar("abrir com senha errada -> 401",
          cliente.post(f"/cofres/{cofre_id}/abrir",
                       headers={"X-Senha-Mestra": "errada"}).status_code == 401)
verificar("abrir sem cabeçalho -> 422",
          cliente.post(f"/cofres/{cofre_id}/abrir").status_code == 422)
verificar("cofre inexistente -> 404",
          cliente.post("/cofres/00000000-0000-0000-0000-000000000000/abrir",
                       headers=CAB).status_code == 404)
verificar("identificador malformado -> 404",
          cliente.post("/cofres/nao-e-uuid/abrir", headers=CAB).status_code == 404)

base = f"/cofres/{cofre_id}/segredos"
r1 = cliente.post(base, headers=CAB, json={"titulo": "Banco produção",
                  "usuario": "admin", "url": "db.prod", "senha": "S3nh@-do-Banco!"})
r2 = cliente.post(base, headers=CAB, json={"titulo": "Banco testes",
                  "usuario": "admin", "url": "db.test", "senha": "S3nh@-do-Banco!"})
verificar("POST segredos -> 201", r1.status_code == 201 and r2.status_code == 201)
s1, s2 = r1.json()["id"], r2.json()["id"]
verificar("POST segredo sem campo senha -> 422",
          cliente.post(base, headers=CAB, json={"titulo": "x"}).status_code == 422)

r = cliente.get(base, headers=CAB)
verificar("GET lista -> 200 com 2 itens", r.status_code == 200 and len(r.json()) == 2)
verificar("lista não expõe nonce/criptograma/etiqueta/senha",
          all(not ({"nonce", "criptograma", "etiqueta", "senha"} & set(i))
              for i in r.json()))

r = cliente.get(f"{base}/{s1}", headers=CAB)
verificar("GET segredo -> 200 com a senha",
          r.status_code == 200 and r.json()["senha"] == "S3nh@-do-Banco!")
verificar("segredo inexistente -> 404",
          cliente.get(f"{base}/00000000-0000-0000-0000-000000000000",
                      headers=CAB).status_code == 404)

nonce_antigo = SEGREDOS[s1]["nonce"]
r = cliente.put(f"{base}/{s1}", headers=CAB, json={"senha": "Nova#Senha1"})
verificar("PUT -> 200", r.status_code == 200)
verificar("PUT gera nonce novo", SEGREDOS[s1]["nonce"] != nonce_antigo)
verificar("PUT preserva título",
          SEGREDOS[s1]["titulo"] == "Banco produção")
verificar("leitura após PUT devolve a nova senha",
          cliente.get(f"{base}/{s1}", headers=CAB).json()["senha"] == "Nova#Senha1")
cliente.put(f"{base}/{s1}", headers=CAB, json={"senha": "S3nh@-do-Banco!"})

# ---------------------------------------------------------------------------
print("Roteiro de verificação (Etapa 6)")
verificar("Teste 1 — mesma senha, nonces e criptogramas distintos",
          SEGREDOS[s1]["nonce"] != SEGREDOS[s2]["nonce"]
          and SEGREDOS[s1]["criptograma"] != SEGREDOS[s2]["criptograma"])

r = cliente.get(f"{base}/{s1}", headers={"X-Senha-Mestra": "errada"})
verificar("Teste 2 — senha-mestra incorreta -> 401 sem conteúdo",
          r.status_code == 401 and "S3nh@" not in r.text)

despejo = str(list(SEGREDOS.values()))
verificar("Teste 3 — nenhuma senha legível no banco", "S3nh@" not in despejo)

original = SEGREDOS[s1]["criptograma"]
SEGREDOS[s1]["criptograma"] = "X" + original[1:]
r = cliente.get(f"{base}/{s1}", headers=CAB)
verificar("Teste 4 — registro adulterado -> 500 sem texto claro",
          r.status_code == 500 and "S3nh@" not in r.text)
SEGREDOS[s1]["criptograma"] = original

for campo in ("nonce", "criptograma", "etiqueta"):
    SEGREDOS[s2][campo] = SEGREDOS[s1][campo]
r = cliente.get(f"{base}/{s2}", headers=CAB)
verificar("Teste 5 — criptograma copiado de outro registro é recusado",
          r.status_code == 500 and "S3nh@" not in r.text)

r = cliente.delete(f"{base}/{s2}", headers=CAB)
verificar("DELETE -> 200", r.status_code == 200)
verificar("segredo removido -> 404",
          cliente.get(f"{base}/{s2}", headers=CAB).status_code == 404)

print()
print("Todos os testes passaram." if falhas == 0 else f"{falhas} falha(s).")
sys.exit(1 if falhas else 0)
