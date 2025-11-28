"""
API routes for transaction operations.

This module defines the FastAPI routes for transaction-related endpoints.
"""
from fastapi import APIRouter, Response
from http import HTTPStatus

router = APIRouter()


@router.post('/registerOffChain/', status_code=HTTPStatus.NO_CONTENT, tags=["Operations"])
def register_off_chain():
    """
    Register data off-chain (placeholder).

    INSERT in application SGBD.
    In practice, an insert in the application SGBD.
    """
    return Response(status_code=HTTPStatus.NO_CONTENT.value)


@router.post('/rectifyOffChain/', status_code=HTTPStatus.NO_CONTENT, tags=["Transactions"])
def rectify_off_chain():
    """
    Rectify data off-chain (placeholder).

    UPDATE in application SGBD.
    In practice, an update in the application SGBD.
    """
    return Response(status_code=HTTPStatus.NO_CONTENT.value)


@router.post('/removeOffChain/', status_code=HTTPStatus.NO_CONTENT, tags=["Transactions"])
def remove_off_chain():
    """
    Remove data off-chain (placeholder).

    DELETE in application SGBD.
    In practice, a delete in the application SGBD.
    """
    return Response(status_code=HTTPStatus.NO_CONTENT.value)
