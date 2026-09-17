"""Camada de acesso ao banco (Supabase/PostgreSQL).

Não conhece criptografia: apenas lê e grava os campos já codificados.
"""

import os

from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()          # lê o arquivo .env

supabase: Client = create_client(
    os.environ["SUPABASE_URL"],
    os.environ["SUPABASE_KEY"],
)

# Colunas devolvidas na listagem: apenas metadados, nunca nonce/criptograma/etiqueta.
COLUNAS_METADADOS = "id, titulo, usuario, url, criado_em, atualizado_em"


def _primeiro(resposta) -> dict | None:
    registros = resposta.data
    return registros[0] if registros else None


# ---------------------------------------------------------------------------
# Cofres
# ---------------------------------------------------------------------------

def inserir_cofre(cofre_id: str, nome: str, sal_b64: str, iteracoes: int,
                  verificador: tuple[str, str, str]) -> None:
    nonce, criptograma, etiqueta = verificador
    supabase.table("cofres").insert({
        "id": cofre_id,
        "nome": nome,
        "kdf_sal": sal_b64,
        "kdf_iteracoes": iteracoes,
        "verificador_nonce": nonce,
        "verificador_criptograma": criptograma,
        "verificador_etiqueta": etiqueta,
    }).execute()


def buscar_cofre(cofre_id: str) -> dict | None:
    resposta = (supabase.table("cofres").select("*")
                .eq("id", cofre_id).execute())
    return _primeiro(resposta)


# ---------------------------------------------------------------------------
# Segredos
# ---------------------------------------------------------------------------

def inserir_segredo(segredo_id: str, cofre_id: str, titulo: str,
                    usuario: str | None, url: str | None,
                    cifrado: tuple[str, str, str]) -> None:
    nonce, criptograma, etiqueta = cifrado
    supabase.table("segredos").insert({
        "id": segredo_id,
        "cofre_id": cofre_id,
        "titulo": titulo,
        "usuario": usuario,
        "url": url,
        "nonce": nonce,
        "criptograma": criptograma,
        "etiqueta": etiqueta,
    }).execute()


def listar_segredos(cofre_id: str) -> list[dict]:
    resposta = (supabase.table("segredos").select(COLUNAS_METADADOS)
                .eq("cofre_id", cofre_id).order("criado_em").execute())
    return resposta.data


def buscar_segredo(cofre_id: str, segredo_id: str) -> dict | None:
    resposta = (supabase.table("segredos").select("*")
                .eq("id", segredo_id).eq("cofre_id", cofre_id).execute())
    return _primeiro(resposta)


def atualizar_segredo(cofre_id: str, segredo_id: str,
                      cifrado: tuple[str, str, str],
                      metadados: dict, atualizado_em: str) -> None:
    nonce, criptograma, etiqueta = cifrado
    dados = {
        **metadados,
        "nonce": nonce,
        "criptograma": criptograma,
        "etiqueta": etiqueta,
        "atualizado_em": atualizado_em,
    }
    (supabase.table("segredos").update(dados)
     .eq("id", segredo_id).eq("cofre_id", cofre_id).execute())


def remover_segredo(cofre_id: str, segredo_id: str) -> None:
    (supabase.table("segredos").delete()
     .eq("id", segredo_id).eq("cofre_id", cofre_id).execute())
