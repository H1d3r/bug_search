FROM python:3.9
WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt -i https://pypi.douban.com/simple/ --trusted-host pypi.douban.com
EXPOSE 7777
CMD [ "python", "main.py" ]
