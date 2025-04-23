This program was created in order to send a file to another place on your workspace with the intention of security. 

**In order to do so, in the terminal you would:
**
- git clone https://github.com/your-username/fileTransfer.git
cd fileTransfer
- python3 -m venv venv
source venv/bin/activate  OR # On Windows: venv\Scripts\activate
- python3 -m pip install cryptography
- _Starting the server:_ python3 securefile.py server --host localhost --port 8443 --dir ./secure_files
- _Sending a file:_ python3 securefile.py client --host localhost --port 8443 send --file /path/to/your/file.txt
- _List available files:_ python3 securefile.py client --host localhost --port 8443 list
- _Obtaining a file:_ python3 securefile.py client --host localhost --port 8443 get --file filename.txt --output /path/to/save/file.txt 
