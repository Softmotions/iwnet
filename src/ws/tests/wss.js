const https = require("https");
const fs = require("fs");

const server = https.createServer({
  cert: fs.readFileSync("./cert.pem"),
  key: fs.readFileSync("./key.pem"),
});

const WebSocketServer = require("ws").Server;
const port = parseInt(process.argv[2]) || 8444;
const wss = new WebSocketServer({ server });

wss.on("connection", (cc) => {
  console.log("New client");
  cc.on("message", function (message) {
    console.log("message: " + message);
    cc.send("echo: " + message);
  });
});

wss.on("error", (err) => {
  console.error("Error: ", err);
  //fs.writeFileSync("error.txt", `${err}`);
});

server.on("tlsClientError", (err) => {
  console.error("tlsClientError ", err);
});

server.listen(port);
console.log("0542a108-ff0f-47ef-86e3-495fd898a8ee");
