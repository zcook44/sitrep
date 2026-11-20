FROM scratch
COPY dist/sitrep /sitrep
ENV CHECKLIST_ROOT=/data
ENV PORT=8780
EXPOSE 8780
ENTRYPOINT ["/sitrep"]
