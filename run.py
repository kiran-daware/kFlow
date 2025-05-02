# run.py

from kflow import app

# This allows gunicorn to detect the app as run:app
app = app

# below is to directly run using python run.py

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)