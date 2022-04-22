import subprocess
import sys
import runpy

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

#installing packages
install('pycryptodome')
install('matplotlib')
install('ecdsa')
install('cryptography')

#Executing script
subprocess.call(['python','./prueba_proyecto.py'])
