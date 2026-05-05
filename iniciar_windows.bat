@echo off
title Terras de Arathorn - Servidor
color 0A
cls

echo.
echo  ╔═══════════════════════════════════════════╗
echo  ║       TERRAS DE ARATHORN - Servidor       ║
echo  ╚═══════════════════════════════════════════╝
echo.

:: ── Verificar Node.js ────────────────────────────────────────────────────
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo  [ERRO] Node.js nao encontrado!
    echo  Acesse: https://nodejs.org/en/download e instale a versao LTS.
    echo.
    pause
    exit /b 1
)
for /f "tokens=*" %%v in ('node --version') do set NODE_VER=%%v
echo  [OK] Node.js %NODE_VER%

:: ── Verificar server.js ──────────────────────────────────────────────────
if not exist "%~dp0server.js" (
    echo  [ERRO] server.js nao encontrado nesta pasta!
    pause
    exit /b 1
)
echo  [OK] server.js encontrado

:: ── Descobrir IP local automaticamente ───────────────────────────────────
echo.
echo  ─────────────────────────────────────────────────────
echo   Enderecos para acessar o jogo:
echo.
echo     Neste PC:         http://localhost:3000
echo.
echo     Na rede local:
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /R /C:"Endere.o IPv4" /C:"IPv4 Address"') do (
    for /f "tokens=1" %%b in ("%%a") do (
        echo       http://%%b:3000
    )
)
echo  ─────────────────────────────────────────────────────
echo.
echo  Compartilhe o endereco "Na rede local" com quem
echo  estiver no mesmo WiFi/cabo que voce!
echo.
echo  Para parar o servidor: feche esta janela ou Ctrl+C
echo  ═════════════════════════════════════════════════════
echo.

:: ── Liberar porta 3000 no Firewall do Windows (silencioso) ───────────────
netsh advfirewall firewall show rule name="Arathorn-3000" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo  [FIREWALL] Adicionando regra para porta 3000...
    netsh advfirewall firewall add rule name="Arathorn-3000" dir=in action=allow protocol=TCP localport=3000 >nul 2>nul
    if %ERRORLEVEL% EQU 0 (
        echo  [FIREWALL] Porta 3000 liberada com sucesso!
    ) else (
        echo  [FIREWALL] Nao foi possivel liberar automaticamente.
        echo  Se outros jogadores nao conseguirem conectar, execute
        echo  este .bat como Administrador (clique direito - Executar como admin^)
    )
    echo.
)

:: ── Ir para a pasta e iniciar servidor ───────────────────────────────────
cd /d "%~dp0"
node server.js

:: ── Servidor encerrado ────────────────────────────────────────────────────
echo.
echo  [INFO] Servidor encerrado.
pause
