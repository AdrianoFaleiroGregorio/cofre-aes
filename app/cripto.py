"""Módulo de criptografia do cofre.

Concentra derivação de chave (PBKDF2-HMAC-SHA256) e cifragem autenticada
(AES-256-GCM). Não conhece HTTP nem banco de dados.
"""

import base64

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

ITERACOES_PADRAO = 210_000
TAMANHO_CHAVE = 32   # bytes, AES-256
TAMANHO_SAL = 16     # bytes
TAMANHO_NONCE = 12   # bytes, valor recomendado para o GCM

FRASE_VERIFICADORA = "cofre-ok"


# ---------------------------------------------------------------------------
# Codificação
# ---------------------------------------------------------------------------

def para_b64(dados: bytes) -> str:
    """Converte bytes em texto Base64, para gravar no banco."""
    return base64.b64encode(dados).decode("ascii")


def de_b64(texto: str) -> bytes:
    """Converte texto Base64 de volta para bytes, ao ler do banco."""
    return base64.b64decode(texto)


# ---------------------------------------------------------------------------
# Derivação de chave
# ---------------------------------------------------------------------------

def derivar_chave(senha_mestra: str, sal: bytes,
                  iteracoes: int) -> bytes:
    """Transforma a senha-mestra em uma chave de 32 bytes."""
    return PBKDF2(
        senha_mestra,
        sal,
        dkLen=TAMANHO_CHAVE,
        count=iteracoes,
        hmac_hash_module=SHA256,
    )


def gerar_sal() -> bytes:
    """Sorteia um sal novo para um cofre."""
    return get_random_bytes(TAMANHO_SAL)


# ---------------------------------------------------------------------------
# AES-GCM
# ---------------------------------------------------------------------------

def cifrar(chave: bytes, texto_claro: str,
           aad: bytes) -> tuple[str, str, str]:
    """Cifra e devolve (nonce, criptograma, etiqueta) em Base64."""
    nonce = get_random_bytes(TAMANHO_NONCE)
    cifra = AES.new(chave, AES.MODE_GCM, nonce=nonce)
    cifra.update(aad)
    criptograma, etiqueta = cifra.encrypt_and_digest(
        texto_claro.encode("utf-8")
    )
    return para_b64(nonce), para_b64(criptograma), para_b64(etiqueta)


def decifrar(chave: bytes, nonce_b64: str, cripto_b64: str,
             etiqueta_b64: str, aad: bytes) -> str:
    """Decifra e verifica a etiqueta. Lança ValueError na falha."""
    nonce = de_b64(nonce_b64)
    criptograma = de_b64(cripto_b64)
    etiqueta = de_b64(etiqueta_b64)

    cifra = AES.new(chave, AES.MODE_GCM, nonce=nonce)
    cifra.update(aad)
    # ValueError ("MAC check failed") sobe para a camada da API.
    texto_claro = cifra.decrypt_and_verify(criptograma, etiqueta)
    return texto_claro.decode("utf-8")


def montar_aad_segredo(cofre_id: str, segredo_id: str) -> bytes:
    """AAD de um segredo: amarra o criptograma ao cofre e ao registro.

    Usada tanto na cifragem quanto na decifragem, garantindo a mesma cadeia.
    """
    return f"{cofre_id}|{segredo_id}".encode("utf-8")


# ---------------------------------------------------------------------------
# Verificador do cofre
# ---------------------------------------------------------------------------

def criar_verificador(chave: bytes,
                      cofre_id: str) -> tuple[str, str, str]:
    """Cifra a frase fixa, gravada no registro do cofre."""
    return cifrar(chave, FRASE_VERIFICADORA, cofre_id.encode("utf-8"))


def senha_mestra_correta(chave, nonce, cripto,
                         etiqueta, cofre_id) -> bool:
    """Tenta decifrar o verificador. Devolve True ou False."""
    try:
        texto = decifrar(chave, nonce, cripto, etiqueta,
                         cofre_id.encode("utf-8"))
    except ValueError:
        return False
    return texto == FRASE_VERIFICADORA
