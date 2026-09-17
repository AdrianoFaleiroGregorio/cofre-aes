# Cofre de Senhas Corporativo

API que armazena credenciais em PostgreSQL (Supabase) de modo que uma cópia integral do
banco não revele nenhuma senha sem a senha-mestra da equipe. As senhas são cifradas com
**AES-256-GCM** usando uma chave derivada da senha-mestra por **PBKDF2-HMAC-SHA256**.

Projeto de laboratório — Criptografia Aplicada, Módulo 3 (Criptografia Simétrica), PUC Goiás.

## Equipe

| Integrante | Matrícula |
|---|---|
| Adriano Faleiro Gregório | 20241002803231 |

## Estrutura

```
cofre-aes/
├── app/
│   ├── main.py        rotas, códigos de resposta, orquestração
│   ├── cripto.py      PBKDF2, AES-GCM, verificador — sem HTTP nem banco
│   ├── banco.py       acesso ao Supabase — sem criptografia
│   └── modelos.py     modelos Pydantic de entrada e saída
├── sql/esquema.sql    tabelas e políticas
├── testes/
│   ├── resultados.md  os cinco testes e o que se observou
│   ├── evidencias/    capturas de tela
│   ├── roteiro_supabase.py  executa os cinco testes contra a API e o Supabase
│   └── teste_local.py verificação automatizada com banco em memória
├── .env.exemplo
├── requirements.txt
└── README.md
```

## Instalação e execução

Requisitos: Python 3.10 ou superior e um projeto no [Supabase](https://supabase.com).

1. Clone o repositório e crie o ambiente virtual:

   ```bash
   git clone https://github.com/USUARIO/cofre-aes.git
   cd cofre-aes
   python -m venv .venv
   ```

2. Ative o ambiente — Windows (PowerShell): `.venv\Scripts\Activate.ps1`;
   Prompt de Comando: `.venv\Scripts\activate.bat`; Linux/macOS: `source .venv/bin/activate`.

3. Instale as dependências:

   ```bash
   pip install -r requirements.txt
   ```

4. No Supabase, abra **SQL Editor → New query**, cole o conteúdo de
   [`sql/esquema.sql`](sql/esquema.sql) e execute com **Run**.

5. Copie `.env.exemplo` para `.env` e preencha com a URL do projeto e a chave pública
   (anon/publishable), obtidas em **Project Settings → API Keys**.

6. Inicie o servidor:

   ```bash
   uvicorn app.main:app --reload
   ```

7. Abra <http://127.0.0.1:8000/docs> para testar as rotas pela interface interativa.

Para validar o código sem acessar o Supabase (banco substituído por um dicionário em memória):

```bash
python -m testes.teste_local
```

Com o servidor em execução e o `.env` configurado, o roteiro de verificação completo
(cinco testes da Etapa 6) roda contra o Supabase com:

```bash
python -m testes.roteiro_supabase
```

## Rotas

Todas as rotas, exceto a criação do cofre, exigem o cabeçalho `X-Senha-Mestra`. A senha-mestra
trafega em cabeçalho, e não na URL ou no corpo, para não aparecer em logs de acesso nem no
histórico do navegador.

| Método e rota | Comportamento | Sucesso |
|---|---|---|
| `POST /cofres` | Gera sal, deriva a chave, cria o verificador e grava o cofre | 201 |
| `POST /cofres/{id}/abrir` | Confere a senha-mestra contra o verificador | 200 |
| `POST /cofres/{id}/segredos` | Cifra e grava uma credencial | 201 |
| `GET /cofres/{id}/segredos` | Lista metadados (id, título, usuário, URL, datas) — nunca senhas | 200 |
| `GET /cofres/{id}/segredos/{sid}` | Decifra e devolve a credencial | 200 |
| `PUT /cofres/{id}/segredos/{sid}` | Substitui a senha com nonce novo; título/usuário/URL opcionais | 200 |
| `DELETE /cofres/{id}/segredos/{sid}` | Remove o registro | 200 |

Códigos de erro:

| Código | Situação |
|---|---|
| 401 | Verificador falhou: senha-mestra incorreta |
| 404 | Cofre ou segredo inexistente (inclui identificador malformado) |
| 422 | Corpo ou cabeçalho em formato inválido (gerado pelo FastAPI) |
| 500 | Verificador aprovado, mas a etiqueta do segredo não confere: registro adulterado |

### Exemplos

Criar um cofre:

```bash
curl -X POST http://127.0.0.1:8000/cofres \
  -H "Content-Type: application/json" \
  -d '{"nome": "Equipe de Sustentação", "senha_mestra": "eq07-cofre-2026"}'
```

```json
{"id": "3f2b8c10-9e44-4d0b-8a71-6c5d2e0f4a19"}
```

Cadastrar uma credencial:

```bash
curl -X POST http://127.0.0.1:8000/cofres/3f2b8c10-9e44-4d0b-8a71-6c5d2e0f4a19/segredos \
  -H "Content-Type: application/json" \
  -H "X-Senha-Mestra: eq07-cofre-2026" \
  -d '{"titulo": "Banco produção", "usuario": "admin", "url": "db.interno", "senha": "S3nh@-do-Banco!"}'
```

```json
{"id": "b1d7e2a4-05c8-4f39-9b62-77ae3c1d80f5"}
```

Ler a credencial:

```bash
curl http://127.0.0.1:8000/cofres/3f2b8c10-9e44-4d0b-8a71-6c5d2e0f4a19/segredos/b1d7e2a4-05c8-4f39-9b62-77ae3c1d80f5 \
  -H "X-Senha-Mestra: eq07-cofre-2026"
```

```json
{
  "id": "b1d7e2a4-05c8-4f39-9b62-77ae3c1d80f5",
  "titulo": "Banco produção",
  "usuario": "admin",
  "url": "db.interno",
  "senha": "S3nh@-do-Banco!"
}
```

Mesma leitura com senha-mestra errada:

```json
HTTP 401
{"detail": "senha-mestra incorreta"}
```

Atualizar a senha:

```bash
curl -X PUT http://127.0.0.1:8000/cofres/3f2b8c10-.../segredos/b1d7e2a4-... \
  -H "Content-Type: application/json" \
  -H "X-Senha-Mestra: eq07-cofre-2026" \
  -d '{"senha": "N0va-S3nha!"}'
```

```json
{"detail": "segredo atualizado"}
```

## Parâmetros criptográficos

| Parâmetro | Valor | Justificativa |
|---|---|---|
| Cifra | AES-256-GCM | Cifra autenticada: confidencialidade e integridade na mesma operação. Qualquer alteração do criptograma, nonce ou etiqueta é detectada antes de devolver texto claro. ECB e CBC não oferecem integridade. |
| Chave | 32 bytes | Tamanho exigido pelo AES-256. |
| KDF | PBKDF2-HMAC-SHA256 | Converte a senha-mestra (curta, previsível) em 32 bytes de aparência aleatória. O SHA-256 é informado explicitamente, pois o padrão da PyCryptodome é SHA-1. |
| Iterações | 210 000, gravadas por cofre | Torna cada tentativa de adivinhação ~200 mil vezes mais cara para o atacante, com custo de uma fração de segundo por requisição legítima (valor recomendado pelo OWASP para PBKDF2-HMAC-SHA256). Guardar o número por cofre permite elevar o padrão no futuro sem impedir a abertura de cofres antigos. |
| Sal | 16 bytes aleatórios, um por cofre, em claro | Impede tabelas pré-calculadas e garante que cofres com a mesma senha-mestra tenham chaves diferentes. Não é secreto. |
| Nonce | 12 bytes aleatórios a cada cifragem, inclusive no `PUT` | Tamanho recomendado para o GCM. Repetir nonce com a mesma chave revelaria o XOR dos textos claros e comprometeria a autenticação. É gerado dentro de `cifrar()`, portanto não há caminho de código que reutilize um nonce. |
| Etiqueta | 16 bytes | Tamanho máximo do GCM, maior resistência a falsificação. |
| AAD dos segredos | `"{cofre_id}\|{segredo_id}"` | Amarra o criptograma ao seu registro: copiar nonce/criptograma/etiqueta para outro segredo faz a etiqueta falhar. Montado por uma única função (`montar_aad_segredo`) usada na cifragem e na decifragem. |
| AAD do verificador | `"{cofre_id}"` | Amarra o verificador ao cofre. |
| Verificador | AES-GCM da frase `cofre-ok` | Distingue senha-mestra errada (401) de registro adulterado (500) sem armazenar a senha-mestra nem valor reversível a partir dela. |

A chave derivada e a senha-mestra existem apenas em variáveis locais durante a requisição;
não são gravadas no banco, não ficam em cache entre requisições e não são registradas em log.

## Limitações

O sistema protege contra cópia integral do banco, leitura direta das tabelas e alteração
maliciosa de registros. **Não** protege contra as situações abaixo, que estão fora do escopo:

- **Servidor de aplicação comprometido.** A senha-mestra e a chave derivada passam pela
  memória do servidor a cada requisição. Quem controla o processo pode capturá-las.
- **Senha-mestra fraca ou divulgada.** A segurança de todo o cofre equivale à dessa senha.
  As 210 000 iterações encarecem ataques de dicionário, mas não salvam uma senha óbvia.
  Não há troca de senha-mestra (exigiria recifrar todos os segredos) nem múltiplos
  usuários com credenciais próprias: toda a equipe compartilha a mesma senha.
- **Auditoria.** Não há registro de quem acessou qual segredo, nem quando.
- **Metadados em claro.** Título, usuário e URL ficam legíveis no banco para permitir
  listagens. Quem obtiver o banco saberá quais sistemas a equipe acessa, com quais nomes de
  usuário e em quais endereços — informação útil para phishing e para escolher alvos —,
  ainda que não obtenha as senhas. Esses campos também não estão cobertos pela etiqueta:
  um invasor com escrita pode trocar o título de um registro sem ser detectado.
- **Exclusão e substituição de registros.** O GCM detecta alteração de um registro, mas não
  a remoção de um segredo nem a restauração de uma versão antiga completa (nonce,
  criptograma e etiqueta anteriores do mesmo registro), que continua válida.
- **Força bruta pela API.** Não há limitação de tentativas na rota; um atacante com acesso
  à API pode testar senhas-mestras (lentamente, pelo custo do PBKDF2).
- **Transporte.** Em execução local a API usa HTTP. Em produção seria obrigatório HTTPS, já
  que a senha-mestra e as senhas decifradas trafegam na requisição e na resposta.
- **Políticas de acesso amplas.** As políticas RLS do laboratório liberam leitura e escrita
  a qualquer portador da chave pública. É intencional para simular o invasor; em produção,
  as tabelas seriam acessíveis apenas pelo servidor.

## Referências

- NIST SP 800-38D — *Recommendation for Block Cipher Modes of Operation: GCM and GMAC*.
- NIST SP 800-132 — *Recommendation for Password-Based Key Derivation*.
- OWASP — *Password Storage Cheat Sheet*.
- Documentação da [PyCryptodome](https://pycryptodome.readthedocs.io) e do [FastAPI](https://fastapi.tiangolo.com).
