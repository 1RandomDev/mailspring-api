FROM node:lts-alpine

COPY . /app
RUN mkdir /data && ln -s /data /app/data
RUN chown -R 1000:1000 /app

ENV NODE_ENV=production
WORKDIR /app
USER 1000:1000
RUN npm install --omit=dev

EXPOSE 5101
VOLUME ["/data"]

ENTRYPOINT ["node", "index.js"]
