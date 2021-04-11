FROM python:3.8.8
WORKDIR /usr/src/app
COPY requirements.txt .

RUN pip3 install --no-cache -r requirements.txt

COPY . .

CMD ["python3", "app.py"]