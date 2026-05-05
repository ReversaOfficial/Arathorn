@echo off
:: Este arquivo PRECISA ser executado como Administrador
title Arathorn - Liberando Firewall (ADMIN)
color 0C
cls

:: Verificar se e administrador
net session >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo  [ERRO] Execute este arquivo como ADMINISTRADOR!
    echo.
    echo  Clique com o botao direito no arquivo e escolha:
    echo  "Executar como administrador"
    echo.
    pause
    exit /b 1
)

echo.
echo  ╔═══════════════════════════════════════════╗
echo  ║   LIBERANDO FIREWALL - MODO ADMIN         ║
echo  ╚═══════════════════════════════════════════╝
echo.

:: Remover regras antigas
echo  Removendo regras antigas...
netsh advfirewall firewall delete rule name="Arathorn-3000" >nul 2>nul
netsh advfirewall firewall delete rule name="Arathorn-3000-IN" >nul 2>nul
netsh advfirewall firewall delete rule name="Arathorn-3000-OUT" >nul 2>nul

:: Adicionar regras novas (entrada E saida)
echo  Adicionando regras de entrada...
netsh advfirewall firewall add rule name="Arathorn-3000-IN" dir=in action=allow protocol=TCP localport=3000 profile=any
echo  Adicionando regras de saida...
netsh advfirewall firewall add rule name="Arathorn-3000-OUT" dir=out action=allow protocol=TCP localport=3000 profile=any

:: Liberar o proprio node.exe tambem
echo  Liberando Node.js no firewall...
for /f "tokens=*" %%n in ('where node') do (
    netsh advfirewall firewall add rule name="NodeJS-Arathorn" dir=in action=allow program="%%n" enable=yes profile=any >nul 2>nul
    echo  Node.js encontrado em: %%n
)

echo.
echo  ════════════════════════════════════════════
echo   FEITO! Regras adicionadas com sucesso.
echo.
echo   Agora inicie o servidor e tente novamente.
echo   Use: iniciar_windows.bat
echo  ════════════════════════════════════════════
echo.
pause
