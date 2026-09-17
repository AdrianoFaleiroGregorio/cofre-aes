"""Formato dos dados que entram e saem da API."""

from datetime import datetime

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Entrada
# ---------------------------------------------------------------------------

class NovoCofre(BaseModel):
    nome: str = Field(min_length=1)
    senha_mestra: str = Field(min_length=1)


class NovoSegredo(BaseModel):
    titulo: str = Field(min_length=1)
    usuario: str | None = None
    url: str | None = None
    senha: str


class AtualizacaoSegredo(BaseModel):
    """Substitui a senha; metadados omitidos permanecem inalterados."""
    senha: str
    titulo: str | None = Field(default=None, min_length=1)
    usuario: str | None = None
    url: str | None = None


# ---------------------------------------------------------------------------
# Saída
# ---------------------------------------------------------------------------

class CofreCriado(BaseModel):
    id: str


class SegredoCriado(BaseModel):
    id: str


class Mensagem(BaseModel):
    detail: str


class MetadadosSegredo(BaseModel):
    id: str
    titulo: str
    usuario: str | None = None
    url: str | None = None
    criado_em: datetime
    atualizado_em: datetime


class SegredoDecifrado(BaseModel):
    id: str
    titulo: str
    usuario: str | None = None
    url: str | None = None
    senha: str
