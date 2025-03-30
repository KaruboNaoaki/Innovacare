# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create .env file (see .env.example)

# Initialize database
flask shell
# Inside Flask shell:
from config import db
db.create_all()
# Exit shell with Ctrl+D

# Run development server
flask run --cert=adhoc

# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Create .env file (see .env.example)

# Start development server
npm start

Acknowledgments

This project was created as a response to the "Secure Healthcare Data Management" challenge by A Little Bit of Hope.
