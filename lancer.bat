@echo off
echo.
echo  NETGUARD - Installation et lancement
echo ========================================
echo.

echo [1/2] Installation des dependances...
pip install flask rich

echo.
echo [2/2] Lancement de NETGUARD...
echo.
echo  Ouvre ton navigateur sur : http://localhost:5000
echo.
python app.py
pause
