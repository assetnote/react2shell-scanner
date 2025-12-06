FROM python:3.12.12-alpine
WORKDIR /opt/react2shell
RUN --mount=type=bind,src=requirements.txt,target=/opt/react2shell/requirements.txt \
     pip install -r requirements.txt
COPY ["scanner.py", "."]
ENTRYPOINT ["python3", "scanner.py"]