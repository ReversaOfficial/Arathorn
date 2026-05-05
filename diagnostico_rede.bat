@echo off
title Arathorn - Diagnostico de Rede
color 0E
cls

echo.
echo  ╔═══════════════════════════════════════════╗
echo  ║     ARATHORN - Diagnostico de Rede        ║
echo  ╚═══════════════════════════════════════════╝
echo.

:: ── IPs do computador ────────────────────────────────────────────────────
echo  === SEUS ENDERECOS IP ===
echo.
ipconfig | findstr /R /C:"IPv4" /C:"IPv4 Address" /C:"Endere.o IPv4"
echo.

:: ── Checar se servidor esta rodando na porta 3000 ────────────────────────
echo  === SERVIDOR NA PORTA 3000 ===
echo.
netstat -an | findstr ":3000"
if %ERRORLEVEL% NEQ 0 (
    echo  [!] Nenhum processo escutando na porta 3000
    echo      Inicie o servidor primeiro com iniciar_windows.bat
) else (
    echo  [OK] Porta 3000 ativa - verifique se aparece 0.0.0.0:3000
    echo       Se aparecer 127.0.0.1:3000 = problema no server.js
    echo       Se aparecer 0.0.0.0:3000  = servidor OK, problema e firewall
)
echo.

:: ── Regras de firewall para porta 3000 ───────────────────────────────────
echo  === REGRAS DE FIREWALL PORTA 3000 ===
echo.
netsh advfirewall firewall show rule name=all | findstr /C:"3000" /C:"Arathorn"
if %ERRORLEVEL% NEQ 0 (
    echo  [!] Nenhuma regra encontrada para porta 3000
)
echo.

:: ── Remover regra antiga e criar nova (requer admin) ─────────────────────
echo  === LIBERANDO PORTA 3000 NO FIREWALL ===
echo.
netsh advfirewall firewall delete rule name="Arathorn-3000" >nul 2>nul
netsh advfirewall firewall add rule name="Arathorn-3000-IN" dir=in action=allow protocol=TCP localport=3000
netsh advfirewall firewall add rule name="Arathorn-3000-OUT" dir=out action=allow protocol=TCP localport=3000
echo.

:: ── Teste de conectividade local ─────────────────────────────────────────
echo  === TESTE LOCAL (localhost:3000) ===
echo.
curl -s -m 3 http://localhost:3000 >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo  [OK] localhost:3000 respondeu!
) else (
    echo  [!] localhost:3000 nao respondeu
    echo      Verifique se o servidor esta rodando
)
echo.

:: ── Mostrar IP para compartilhar ─────────────────────────────────────────
echo  === IP PARA COMPARTILHAR NA REDE ===
echo.
echo  Passe este endereco para quem esta na mesma rede:
echo.
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /R /C:"IPv4 Address" /C:"Endere.o IPv4"') do (
    for /f "tokens=1" %%b in ("%%a") do (
        echo      http://%%b:3000
    )
)
echo.
echo  ─────────────────────────────────────────────────────
echo  Se ainda nao funcionar:
echo  1. Desative o Firewall do Windows TEMPORARIAMENTE
echo     Painel de Controle > Firewall > Desativar
echo     (so para testar, reative depois)
echo  2. Se funcionar sem o firewall = problema era firewall
echo     Adicione excecao manualmente para o Node.js
echo  ─────────────────────────────────────────────────────
echo.
pause
