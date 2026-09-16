#!/usr/bin/env node
"use strict";

const http = require("http");

const [method, target, ...rawHeaders] = process.argv.slice(2);
if (!method || !target) {
  process.exit(2);
}
const headers = {};
for (const raw of rawHeaders) {
  const split = raw.indexOf("=");
  if (split <= 0) {
    process.exit(2);
  }
  headers[raw.slice(0, split)] = raw.slice(split + 1);
}

const chunks = [];
process.stdin.on("data", (chunk) => chunks.push(chunk));
process.stdin.on("end", () => {
  const request = http.request(target, {
    method,
    headers,
    timeout: 20000,
  }, (response) => {
    const responseChunks = [];
    response.on("data", (chunk) => responseChunks.push(chunk));
    response.on("end", () => {
      if (response.statusCode < 200 || response.statusCode >= 300) {
        process.exitCode = 22;
        return;
      }
      process.stdout.write(Buffer.concat(responseChunks));
    });
  });
  request.on("timeout", () => request.destroy(new Error("request timed out")));
  request.on("error", () => {
    process.exitCode = 7;
  });
  const body = Buffer.concat(chunks);
  if (body.length) {
    request.write(body);
  }
  request.end();
});
