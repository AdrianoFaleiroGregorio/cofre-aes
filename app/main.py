"""Rotas da API do cofre: orquestra as camadas de criptografia e de banco."""

import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException, status

from app import banco, cripto
from app.modelos import (
    AtualizacaoSegredo,
    CofreCriado,
    Mensagem,
    MetadadosSegredo,
    NovoCofre,
    NovoSegredo,
    SegredoCriado,
    SegredoDecifrado,
)

app = FastAPI(
    title="Cofre de Senhas",
    description="API que protege credenciais com AES-256-GCM e PBKDF2-HMAC-SHA256.",
)

ERROS_COMUNS = {
    401: {"model": Mensagem, "description": "Senha-mestra incorreta"},
    404: {"model": Mensagem, "description": "Cofre ou segredo inexistente"},
}


# ---------------------------------------------------------------------------
# Auxiliares
# ---------------------------------------------------------------------------

def _validar_uuid(valor: str, recurso: str) -> str:
    """Identificadores malformados não existem: responde 404 sem ir ao banco."""
    try:
        return str(uuid.UUID(valor))
    except ValueError:
        raise HTTPException(status_code=404, detail=f"{recurso} não encontrado")


def _abrir_cofre(cofre_id: str, senha_mestra: str) -> bytes:
    """Busca o cofre, deriva a chave e confere o verificador.

    Devolve a chave derivada, que vive apenas durante a requisição.
    """
    cofre_id = _validar_uuid(cofre_id, "cofre")
    cofre = banco.buscar_cofre(cofre_id)
    if cofre is None:
        raise HTTPException(status_code=404, detail="cofre não encontrado")

    chave = cripto.derivar_chave(
        senha_mestra,
        cripto.de_b64(cofre["kdf_sal"]),
        cofre["kdf_iteracoes"],
    )
    if not cripto.senha_mestra_correta(
        chave,
        cofre["verificador_nonce"],
        cofre["verificador_criptograma"],
        cofre["verificador_etiqueta"],
        cofre_id,
    ):
        raise HTTPException(status_code=401, detail="senha-mestra incorreta")
    return chave


def _buscar_segredo(cofre_id: str, segredo_id: str) -> dict:
    segredo_id = _validar_uuid(segredo_id, "segredo")
    segredo = banco.buscar_segredo(cofre_id, segredo_id)
    if segredo is None:
        raise HTTPException(status_code=404, detail="segredo não encontrado")
    return segredo


# ---------------------------------------------------------------------------
# Cofres
# ---------------------------------------------------------------------------

@app.post("/cofres", status_code=status.HTTP_201_CREATED,
          response_model=CofreCriado)
def criar_cofre(dados: NovoCofre):
    cofre_id = str(uuid.uuid4())
    sal = cripto.gerar_sal()
    iteracoes = cripto.ITERACOES_PADRAO

    chave = cripto.derivar_chave(dados.senha_mestra, sal, iteracoes)
    verificador = cripto.criar_verificador(chave, cofre_id)

    banco.inserir_cofre(cofre_id, dados.nome, cripto.para_b64(sal),
                        iteracoes, verificador)
    return CofreCriado(id=cofre_id)


@app.post("/cofres/{cofre_id}/abrir", response_model=Mensagem,
          responses=ERROS_COMUNS)
def abrir_cofre(cofre_id: str, x_senha_mestra: str = Header(...)):
    _abrir_cofre(cofre_id, x_senha_mestra)
    return Mensagem(detail="senha-mestra correta")


# ---------------------------------------------------------------------------
# Segredos
# ---------------------------------------------------------------------------

@app.post("/cofres/{cofre_id}/segredos", status_code=status.HTTP_201_CREATED,
          response_model=SegredoCriado, responses=ERROS_COMUNS)
def criar_segredo(cofre_id: str, dados: NovoSegredo,
                  x_senha_mestra: str = Header(...)):
    chave = _abrir_cofre(cofre_id, x_senha_mestra)
    cofre_id = str(uuid.UUID(cofre_id))
    segredo_id = str(uuid.uuid4())

    aad = cripto.montar_aad_segredo(cofre_id, segredo_id)
    cifrado = cripto.cifrar(chave, dados.senha, aad)

    banco.inserir_segredo(segredo_id, cofre_id, dados.titulo,
                          dados.usuario, dados.url, cifrado)
    return SegredoCriado(id=segredo_id)


@app.get("/cofres/{cofre_id}/segredos",
         response_model=list[MetadadosSegredo], responses=ERROS_COMUNS)
def listar_segredos(cofre_id: str, x_senha_mestra: str = Header(...)):
    _abrir_cofre(cofre_id, x_senha_mestra)
    return banco.listar_segredos(str(uuid.UUID(cofre_id)))


@app.get("/cofres/{cofre_id}/segredos/{segredo_id}",
         response_model=SegredoDecifrado,
         responses={**ERROS_COMUNS,
                    500: {"model": Mensagem, "description": "Registro adulterado"}})
def ler_segredo(cofre_id: str, segredo_id: str,
                x_senha_mestra: str = Header(...)):
    chave = _abrir_cofre(cofre_id, x_senha_mestra)
    cofre_id = str(uuid.UUID(cofre_id))
    segredo = _buscar_segredo(cofre_id, segredo_id)

    aad = cripto.montar_aad_segredo(cofre_id, segredo["id"])
    try:
        senha = cripto.decifrar(chave, segredo["nonce"],
                                segredo["criptograma"],
                                segredo["etiqueta"], aad)
    except ValueError:
        # O verificador passou, logo a chave está correta: o registro
        # foi alterado (criptograma, nonce, etiqueta ou troca entre registros).
        raise HTTPException(
            status_code=500,
            detail="registro adulterado: falha na verificação da etiqueta",
        )

    return SegredoDecifrado(
        id=segredo["id"],
        titulo=segredo["titulo"],
        usuario=segredo["usuario"],
        url=segredo["url"],
        senha=senha,
    )


@app.put("/cofres/{cofre_id}/segredos/{segredo_id}", response_model=Mensagem,
         responses=ERROS_COMUNS)
def atualizar_segredo(cofre_id: str, segredo_id: str,
                      dados: AtualizacaoSegredo,
                      x_senha_mestra: str = Header(...)):
    chave = _abrir_cofre(cofre_id, x_senha_mestra)
    cofre_id = str(uuid.UUID(cofre_id))
    segredo = _buscar_segredo(cofre_id, segredo_id)

    # cifrar() sorteia um nonce novo a cada chamada: o antigo nunca é reutilizado.
    aad = cripto.montar_aad_segredo(cofre_id, segredo["id"])
    cifrado = cripto.cifrar(chave, dados.senha, aad)

    metadados = dados.model_dump(exclude={"senha"}, exclude_unset=True)
    if metadados.get("titulo") is None:
        metadados.pop("titulo", None)   # coluna not null
    banco.atualizar_segredo(cofre_id, segredo["id"], cifrado, metadados,
                            datetime.now(timezone.utc).isoformat())
    return Mensagem(detail="segredo atualizado")


@app.delete("/cofres/{cofre_id}/segredos/{segredo_id}", response_model=Mensagem,
            responses=ERROS_COMUNS)
def remover_segredo(cofre_id: str, segredo_id: str,
                    x_senha_mestra: str = Header(...)):
    _abrir_cofre(cofre_id, x_senha_mestra)
    cofre_id = str(uuid.UUID(cofre_id))
    segredo = _buscar_segredo(cofre_id, segredo_id)

    banco.remover_segredo(cofre_id, segredo["id"])
    return Mensagem(detail="segredo removido")
