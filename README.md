## What to do in the Terminal:

- ```
  git clone https://github.com/your-username/fileTransfer.git
  cd fileTransfer
  ```

- ```
  python3 -m venv venv source venv/bin/activate  OR # On Windows: venv\Scripts\activate
  ````

- ```
  python3 -m pip install cryptography
  ```
  
- ```
  Starting the server:_ python3 securefile.py server --host localhost --port 8443 --dir ./secure_files
  ```
  
- ```
  Sending a file:_ python3 securefile.py client --host localhost --port 8443 send --file /path/to/your/file.txt
  ```
  
- ```
  List available files:_ python3 securefile.py client --host localhost --port 8443 list
  ```
  
- ```
  Obtaining a file:_ python3 securefile.py client --host localhost --port 8443 get --file filename.txt --output /path/to/save/file.txt
  ```

Send a file to another place in your workspace to create security
