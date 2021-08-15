const WebSocketServer = require('ws').Server;
const port = parseInt(process.argv[2]) || 8080;
const wss = new WebSocketServer({ port });

wss.on('connection', function connection(cc) {
  console.log('New client');
  cc.on('message', function (message) {
    console.log('message: ' + message);
    cc.send('echo: ' + message);
  });
});

//console.log(`Listening on port: ${port}`);
console.log('0542a108-ff0f-47ef-86e3-495fd898a8ee');
