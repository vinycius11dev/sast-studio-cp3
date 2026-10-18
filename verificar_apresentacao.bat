@echo off
chcp 65001 >nul
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo Python nao foi encontrado. Instale Python 3 e tente novamente.
    pause
    exit /b 1
)

echo Verificando API, exemplos, gate, relatorios e IA real...
echo Deixe iniciar.bat e o Ollama abertos antes de continuar.
echo.
python -m scripts.smoke --require-llm
set "RESULT=%ERRORLEVEL%"

echo.
if not "%RESULT%"=="0" (
    echo A verificacao falhou. Leia a mensagem acima, corrija o item indicado e rode este arquivo novamente.
) else (
    echo O sistema esta pronto para o ensaio da apresentacao.
)
pause
exit /b %RESULT%
