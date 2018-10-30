const multihashes = require('multihashes');
const crypto = require('crypto');
const crypto2 = require('libp2p-crypto');
const BufferShift = require("buffershift");
const bs58 = require('bs58');
const protobuf = require('protobufjs');
const nacl = require('tweetnacl');
const sha256 = require('js-sha256');
const Base64 = require('js-base64').Base64;
const ed2curve = require('ed2curve');
const bip39 = require('bip39');
const request = require("request");
const PeerId = require('peer-id');
const IPFS = require('ipfs');
const PeerInfo = require('peer-info');
const pull = require('pull-stream')
const libp2p = require('libp2p');

localStorage.debug = '*';


var identity_key = "";
var relay_server = "wss://webchat.ob1.io:8080";
var mnemonic = ""; // You can use this from your other OpenBazaar install backup or leave empty
var subscription_key = "";
var jsonDescriptor = require("./message.json");
var ephem_keypair = "";
var my_peer_id = "";
var root = protobuf.Root.fromJSON(jsonDescriptor);

var ws = "";

const options = {
      EXPERIMENTAL: {
        pubsub: true
      },
      relay: {
        "enabled": true,
        "hop": {
          "enabled": true
        }
      },
      repo: 'ipfs/ipfs-node1'
    }

    node = new IPFS(options)

  node.on('ready', () => {

    node.id(function (err, identity) {
      if (err) {
        throw err
      }
      console.log(identity)
    })

    document.getElementById('peerid').innerHTML = node._peerInfo.id._idB58String;

    my_peer_id = node._peerInfo.id._idB58String;

    //peer = "/ip4/138.68.5.113/tcp/9005/ws/ipfs/QmPPg2qeF3n2KvTRXRZLaTwHCw8JxzF4uZK93RfMoDvf2o"; // Push Node 1
    peer = "/dns4/webchat.ob1.io/tcp/9999/wss/ipfs/QmVc37Xishzc8R3ZXn1p4Mm27nkSWhGSVdRr9Zi3NPRq8V"; // Webchat Relay Circuit Hop
    node.swarm.connect(peer, (err) => {
      if (err) {
        return console.error(err)
      }
      console.log("Connected to peer: ", peer);

      function logger (read) {

        read(null, function next(end, data) {
          if(end === true || data == "") return
          if(end) throw end

          console.log("Received custom protocol data from OB desktop node:", data, end)

          read(null, next)
        })
      }

      node._libp2pNode.handle('/openbazaar/app/1.0.0', (protocol, conn) => {

        console.log('Handling /openbazaar/app/1.0.0 protocol', protocol, conn)
        pull(
          conn,
          pull.map((v) => v.toString()),
          logger
        )
      });

    })
  })

function getChatPayload(message) {
  var subject = ""; // Empty subject for chat message
  var timestamp = new Date();
  var timestamp_secs = Math.floor(timestamp / 1000);
  const combinationString = subject + "!" + timestamp.toISOString();

  var idBytes = crypto.createHash('sha256').update(combinationString).digest();
  var idBytesArray = new Uint8Array(idBytes);
  var idBytesBuffer =  new Buffer(idBytesArray.buffer);
  var encoded = multihashes.encode(idBytesBuffer,0x12);

  var payload = {
    messageId: multihashes.toB58String(encoded),
    subject: "",
    message: message || "TEST",
    timestamp: { seconds: timestamp_secs, nanos: 0},
    flag: 0
  };

  return payload;
}

/***************
/* Call these methods from the browser
****************/

window.sendMessage = function sendMessage(peerid, message) {
  pingDesktop(peerid, message);
}

window.generatePeerID = (cb) => {
  if(!mnemonic) {
    console.log("No mnemonic set...");
    mnemonic = bip39.generateMnemonic();
    console.log("Generated mnemonic:", mnemonic);
  }
  var bip39seed = bip39.mnemonicToSeed(mnemonic, 'Secret Passphrase');
  var hmac = sha256.hmac.create("OpenBazaar seed");
  hmac.update(bip39seed);
  var seed = new Uint8Array(hmac.array());
  crypto2.keys.generateKeyPairFromSeed('ed25519', seed, (err, keypair)=>{
    var peerid = PeerId.createFromPubKey(crypto2.keys.marshalPublicKey(keypair.public), (err, key)=>{
      console.log("Peer ID:", key._idB58String);
      my_peer_id = key._idB58String;
      cb({
        "mnemonic": mnemonic,
        "peerid": key._idB58String
      });
    });

  });
}

window.pingDesktop = (peerid, message) => {

  peer = "/p2p-circuit/ipfs/" + peerid;

  node.swarm.connect(peer, (err) => {
    if (err) {
      return console.error("Error", err)
    }
    console.log("Connected to peer:", peer);

    node.swarm.peers((err, peerInfos) => {
      if (err) {
        throw err
      }
      console.log("PEER INFO", peerInfos)
    });


    // Send message to desktop node
    node._libp2pNode.dialProtocol(peer, '/openbazaar/app/1.0.0', (err, conn) => {
      if (err) { throw err }

      console.log('Web Node to Desktop Node on: ', conn)

      var Chat = root.lookupType("Chat");
      var payload = getChatPayload(message);
      console.log("Chat Payload:", payload);

      if(Chat.verify(payload)) {
        console.log("Problem verifying Chat protobuf payload");
      }
      var chatmessage = Chat.create(payload);
      var serializedChat = Chat.encode(chatmessage).finish();

      var Message = root.lookupType("Message");
      var message_payload = {
        messageType: 1,
        payload: {
          type_url: "type.googleapis.com/Chat",
          value: serializedChat
        }
      };
      console.log("Message Payload:", message_payload);

      if(Message.verify(message_payload)) {
        console.log("Problem verifying Message protobuf payload");
      }
      var messageMessage = Message.create(message_payload);
      var serializedMessage = Message.encode(messageMessage).finish();

      console.log("MESSAGE", serializedMessage);

      function sink (read) {
        console.log(this)
        read(null, function next (err, data) {
          if(err) return console.log(err)
          console.log("MY DATA",data)
          //recursively call read again!
          read(null, next)
        })
      }

      pull(
        pull.once(serializedMessage),        
        conn
      )

    })
  })

}
