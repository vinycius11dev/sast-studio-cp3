import ast
import os
from typing import Tuple, Optional


class CodeParser:
    """Responsável por carregar código-fonte e convertê-lo em Árvore de Sintaxe Abstrata (AST)."""

    @staticmethod
    def parse_file(file_path: str) -> Tuple[Optional[ast.AST], str, Optional[str]]:
        """Lê um arquivo do sistema e compila sua AST.

        Retorna:
            (tree, source_code, error_message)
        """
        if not os.path.exists(file_path):
            return None, "", f"Arquivo não encontrado: {file_path}"

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source_code = f.read()
        except UnicodeDecodeError:
            try:
                with open(file_path, "r", encoding="latin-1") as f:
                    source_code = f.read()
            except Exception as e:
                return None, "", f"Erro ao decodificar arquivo {file_path}: {e}"
        except Exception as e:
            return None, "", f"Erro de I/O no arquivo {file_path}: {e}"

        return CodeParser.parse_code(source_code=source_code, filename=file_path)

    @staticmethod
    def parse_code(
        source_code: str, filename: str = "<snippet>"
    ) -> Tuple[Optional[ast.AST], str, Optional[str]]:
        """Compila uma string de código-fonte diretamente para AST.

        Retorna:
            (tree, source_code, error_message)
        """
        try:
            tree = ast.parse(source_code, filename=filename)
            return tree, source_code, None
        except SyntaxError as se:
            error_msg = f"Erro de sintaxe em {filename} (linha {se.lineno}, col {se.offset}): {se.msg}"
            return None, source_code, error_msg
        except Exception as e:
            return None, source_code, f"Erro inesperado no parsing de {filename}: {e}"
