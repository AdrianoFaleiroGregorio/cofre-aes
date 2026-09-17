# Roteiro de verificação — resultados

**Ambiente:** API executada localmente (`uvicorn app.main:app`) contra o projeto Supabase
`cofre-aes-equipe07` (região sa-east-1).

**Evidências:**
- [`evidencias/saida_roteiro.txt`](evidencias/saida_roteiro.txt) — saída completa do terminal,
  gerada por `python -m testes.roteiro_supabase`, que executa os cinco testes pela API e faz as
  adulterações diretamente no Supabase com a chave pública (o acesso de um invasor).
- Capturas de tela:
  - [`teste1_e_3_consulta_direta.png`](evidencias/teste1_e_3_consulta_direta.png) — consulta direta no SQL Editor (Testes 1 e 3);
  - [`teste2_401.png`](evidencias/teste2_401.png) — leitura com senha-mestra incorreta no `/docs`;
  - [`teste4_update.png`](evidencias/teste4_update.png) — adulteração do criptograma no SQL Editor;
  - [`teste4_adulterado.png`](evidencias/teste4_adulterado.png) — leitura do registro adulterado no `/docs` (500);
  - [`teste4_restaurado.png`](evidencias/teste4_restaurado.png) — mesma leitura após restaurar o criptograma original (200).

**Resumo:** os cinco testes foram aprovados.

| Teste | Esperado | Observado |
|---|---|---|
| 1 — Nonces distintos | nonce e criptograma diferentes | diferentes ✅ |
| 2 — Senha-mestra incorreta | 401 sem conteúdo | 401 `senha-mestra incorreta` ✅ |
| 3 — O que o invasor enxerga | nenhuma senha legível | apenas Base64 ✅ |
| 4 — Registro adulterado | 500, sem texto claro | 500 `registro adulterado` ✅ |
| 5 — Troca entre registros | leitura recusada | 500 `registro adulterado` ✅ |

Dados usados:

| Item | Valor |
|---|---|
| Cofre | `47cce2e7-c9bb-4cd6-b779-c2380bc48eb5` |
| Senha-mestra | `eq07-cofre-2026` (apenas para o teste) |
| Segredo A — "Banco produção" | `e331e721-9786-4589-9fdb-9b9ceead6e0a` |
| Segredo B — "Banco testes" | `b33a7058-0939-4566-ba1b-37d42d6b8fd9` |
| Senha protegida nos dois | `S3nh@-do-Banco!` |

Antes dos testes, a listagem (`GET /cofres/{id}/segredos`) devolveu apenas `id`, `titulo`,
`usuario`, `url`, `criado_em` e `atualizado_em`, e a leitura do segredo A com a senha-mestra
correta devolveu `S3nh@-do-Banco!` (HTTP 200). Também foram verificados o `PUT` (200, nonce
novo gravado, nova senha lida corretamente) e o `DELETE` (200, leitura posterior 404).

---

## Teste 1 — Nonces distintos

**Procedimento.** Cadastro da mesma senha (`S3nh@-do-Banco!`) nos segredos A e B, via
`POST /cofres/{id}/segredos`, e consulta à tabela `segredos`.

**Esperado.** `nonce` e `criptograma` diferentes nos dois registros.

**Observado.**

| titulo | nonce | criptograma |
|---|---|---|
| Banco produção | `MZJrt++JwXDOpEe5` | `G2ISjMqd14y7mFe5ePGx` |
| Banco testes | `929kHMylWe+C4Zoq` | `B4nQs+BMiJxLLU92ZpDY` |

Nonces e criptogramas não têm relação entre si, embora a senha seja idêntica. Quem olha a
tabela não consegue saber que os dois registros protegem a mesma senha. Os criptogramas têm 15
bytes (20 caracteres em Base64), o mesmo tamanho do texto claro: o GCM não usa preenchimento.

---

## Teste 2 — Senha-mestra incorreta

**Procedimento.** `GET /cofres/{id}/segredos/{A}` com `X-Senha-Mestra: senha-errada`.

**Esperado.** 401, sem conteúdo do segredo.

**Observado.** `HTTP 401`

```json
{"detail": "senha-mestra incorreta"}
```

A chave derivada da senha errada não decifra o verificador `cofre-ok`, e a requisição é
encerrada antes de o segredo ser lido.

---

## Teste 3 — O que o invasor enxerga

**Procedimento.**

```sql
select titulo, usuario, nonce, criptograma, etiqueta
from public.segredos;
```

**Esperado.** Nenhuma senha legível.

**Observado.**

| titulo | usuario | nonce | criptograma | etiqueta |
|---|---|---|---|---|
| Banco produção | admin | `MZJrt++JwXDOpEe5` | `G2ISjMqd14y7mFe5ePGx` | `P8eJo6YDNIVpKTjwXow2Og==` |
| Banco testes | admin | `929kHMylWe+C4Zoq` | `B4nQs+BMiJxLLU92ZpDY` | `uHId3ob4vGgClCciqtLX9g==` |

Nenhuma senha aparece, só cadeias Base64 sem significado. Título e usuário ficam em claro, de
propósito, para que a listagem funcione. Quem obtiver o banco sabe quais sistemas a equipe
acessa, mas não as senhas (ver Limitações no README).

---

## Teste 4 — Registro adulterado

**Procedimento.** Alteração do primeiro caractere do criptograma do segredo A, equivalente a:

```sql
update public.segredos
set criptograma = 'X' || substring(criptograma from 2)
where id = 'e331e721-9786-4589-9fdb-9b9ceead6e0a';
```

`G2ISjMqd14y7mFe5ePGx` → `X2ISjMqd14y7mFe5ePGx`. Em seguida, `GET /cofres/{id}/segredos/{A}`
com a senha-mestra correta.

**Esperado.** 500 indicando adulteração, sem texto claro.

**Observado.** `HTTP 500`

```json
{"detail": "registro adulterado: falha na verificação da etiqueta"}
```

O verificador passou, então a chave estava correta, mas `decrypt_and_verify` lançou
`ValueError: MAC check failed`. A exceção é tratada em `app/main.py` e vira a resposta 500:
nenhum byte do texto claro é devolvido e o servidor não registra traceback. Depois do teste,
o criptograma original foi restaurado.

---

## Teste 5 — Troca de criptogramas entre registros

**Procedimento.** Cópia de `nonce`, `criptograma` e `etiqueta` do segredo A para o segredo B,
equivalente a:

```sql
update public.segredos b
set nonce = a.nonce, criptograma = a.criptograma, etiqueta = a.etiqueta
from public.segredos a
where a.id = 'e331e721-9786-4589-9fdb-9b9ceead6e0a'
  and b.id = 'b33a7058-0939-4566-ba1b-37d42d6b8fd9';
```

Em seguida, leitura de A (controle) e de B com a senha-mestra correta.

**Esperado.** A leitura de B é recusada.

**Observado.**
- A: `HTTP 200`, senha `S3nh@-do-Banco!`. Os três campos copiados são válidos.
- B: `HTTP 500`

```json
{"detail": "registro adulterado: falha na verificação da etiqueta"}
```

A etiqueta foi calculada com o AAD `47cce2e7-…|e331e721-…` (registro A). Ao decifrar no
registro B, a API monta `47cce2e7-…|b33a7058-…`, e a etiqueta não confere. Sem o AAD, a
leitura de B teria devolvido a senha de A como se fosse a de B: a confidencialidade estaria
intacta, mas o sistema teria sido manipulado.
