Setup Instructions

Clone or download the repository
Copygit clone https://github.com/your-username/secure-healthcare-system.git
cd secure-healthcare-system

Create a virtual environment
Copypython -m venv venv
venv\Scripts\activate

Install dependencies
Copypip install -r requirements.txt

Set environment variables
Copyset SECRET_KEY=your_random_secret_key
set ENCRYPTION_KEY=your_random_encryption_key
For permanent environment variables:

Search for "Environment Variables" in Windows
Add under System or User variables


Initialize the database (first run only)
Copyset ALLOW_DB_INIT=1
python app.py

Visit http://127.0.0.1:5000/init-db in your browser
Remove the environment variable after initialization:
Copyset ALLOW_DB_INIT=



Run the application
Copypython app.py

Access the application

Open your browser and go to https://127.0.0.1:5000/

