FROM python:3.12-slim

WORKDIR /app
COPY app /app
COPY config /opt/sitrep
COPY generate_test_data.py /opt/generate_test_data.py
RUN python /opt/generate_test_data.py --out /data

ENV CHECKLIST_ROOT=/data
ENV PORT=8780
EXPOSE 8780

CMD ["sh", "/app/entrypoint.sh"]
