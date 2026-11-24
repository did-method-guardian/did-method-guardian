# Build context is the REPO ROOT (not this directory), so npm's own
# workspace resolution finds packages/lib locally -- the image never waits
# on @did-guardian/lib being published to npm.
#
#   docker build -f packages/uni-resolver-driver/Dockerfile -t driver-did-guardian .
FROM node:20-slim AS build
WORKDIR /repo
COPY package.json package-lock.json ./
COPY packages/lib packages/lib
COPY packages/uni-resolver-driver packages/uni-resolver-driver
RUN npm ci --workspace=packages/lib --workspace=packages/uni-resolver-driver
RUN npm run build --workspace=packages/lib
RUN npm run build --workspace=packages/uni-resolver-driver

FROM node:20-slim
WORKDIR /app
COPY --from=build /repo/node_modules ./node_modules
COPY --from=build /repo/packages/lib/dist /repo/packages/lib/package.json ./node_modules/@did-guardian/lib/
COPY --from=build /repo/packages/uni-resolver-driver/dist ./dist
EXPOSE 8080
CMD ["node", "dist/src/server.js"]
