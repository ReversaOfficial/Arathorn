@echo off
title Terras de Arathorn - Instalador
color 0E
cls

echo.
echo  ╔═══════════════════════════════════════════╗
echo  ║     TERRAS DE ARATHORN - Instalador       ║
echo  ╚═══════════════════════════════════════════╝
echo.
echo  Este script vai verificar e configurar tudo
echo  necessario para rodar o jogo no Windows.
echo.

:: ── Checar Node.js ────────────────────────────────────────────────────────
echo  [1/3] Verificando Node.js...
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo  [!] Node.js NAO encontrado.
    echo.
    echo  Abrindo pagina de download do Node.js...
    echo  Baixe a versao LTS, instale e rode este script novamente.
    echo.
    timeout /t 2 >nul
    start https://nodejs.org/en/download
    pause
    exit /b 1
)
for /f "tokens=*" %%v in ('node --version') do set NODE_VER=%%v
echo  [OK] Node.js %NODE_VER%

:: ── Checar arquivos do jogo ───────────────────────────────────────────────
echo.
echo  [2/3] Verificando arquivos do jogo...
if not exist "%~dp0server.js" (
    echo  [ERRO] server.js nao encontrado nesta pasta!
    echo  Certifique-se que server.js e game.html estao na mesma pasta deste .bat
    pause
    exit /b 1
)
if not exist "%~dp0game.html" (
    echo  [ERRO] game.html nao encontrado nesta pasta!
    pause
    exit /b 1
)
echo  [OK] server.js encontrado
echo  [OK] game.html encontrado

:: ── Criar pasta de backups ────────────────────────────────────────────────
echo.
echo  [3/3] Criando pasta de backups...
cd /d "%~dp0"
if not exist "backups" (
    mkdir backups
    echo  [OK] Pasta backups\ criada
) else (
    echo  [OK] Pasta backups\ ja existe
)

:: ── Tudo pronto! ──────────────────────────────────────────────────────────
echo.
echo  ═══════════════════════════════════════════════
echo   TUDO PRONTO! Use o arquivo:
echo.
echo      iniciar_windows.bat
echo.
echo   para iniciar o servidor.
echo   Depois acesse: http://localhost:3000
echo  ═══════════════════════════════════════════════
echo.
pause
