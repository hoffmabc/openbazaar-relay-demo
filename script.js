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
const PeerId = require('peer-id')


var identity_key = "";
var relay_server = "wss://webchat.ob1.io:8080";
var mnemonic = "";  // You can use this from your other OpenBazaar install backup or leave empty
var subscription_key = "";

var ws = "";

function get_encoded_ciphertext(plaintext, pubkey) {
  var ephem_keypair = nacl.box.keyPair(); // Generate ephemeral key
  var pubkeyCurve = ed2curve.convertPublicKey(pubkey._key); // Convert to curve25519 pubkey
  var nonce = new Uint8Array(crypto.randomBytes(24)); // 24 bit random nonce
  var ciphertext = nacl.box(plaintext, nonce, pubkeyCurve, ephem_keypair.secretKey); // Create ciphertext
  var joint_ciphertext = Buffer.concat([nonce, ephem_keypair.publicKey, ciphertext]); // Append none and key
  var encoded_ciphertext = joint_ciphertext.toString('base64'); // Base 64 encode
  console.log('Encoded Envelope Ciphertext:', encoded_ciphertext.length, encoded_ciphertext);
  return encoded_ciphertext;
}

function generateSubscriptionKey(peerID) {
  console.log('Generate subscription key for: '+peerID);
  var peerIDMultihash = multihashes.fromB58String(peerID);
  var decoded = multihashes.decode(peerIDMultihash);
  var digest = decoded.digest;
  var prefix = new Buffer(new Uint8Array(digest.slice(0,8)));

  var BitArray = require('node-bitarray')
  var bits = BitArray.fromBuffer(prefix);
  bits = bits.slice(0,14);
  bits = new Buffer(bits);

  for(var i=0; i<50;i++) {
    bits = Buffer.concat([new Buffer([0]), bits]);
  }

  // Construct uint8array from binary strings
  var id_array = [];
  for(i=0; i<8; i++) {
    var tmp_x = "";
    for(j=0; j<8; j++) {
      //console.log('bit', i*8+j, bits[i*8+j])
      tmp_x += bits[i*8+j];
    }
    id_array.push(parseInt(tmp_x, 2));
  }

  var checksum = crypto.createHash('sha256').update(new Buffer(id_array)).digest();
  var subscriptionKey = multihashes.encode(Buffer.from(checksum), 'sha2-256');
  console.log('Subscription Key:', bs58.encode(subscriptionKey));
  return bs58.encode(subscriptionKey);
}

function generateMessageEnvelope(peerid, message, cb) {

  // Construct Message for websocket
  var constructMessage = function(jsonDescriptor) {

    var root = protobuf.Root.fromJSON(jsonDescriptor);
    var Message = root.lookupType("Message");
    var Chat = root.lookupType("Chat");
    var Envelope = root.Envelope;
    //var Timestamp = protobuf.common.get('google/protobuf/timestamp.proto');

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

    console.log("Chat Payload:", payload);

    if(Chat.verify(payload)) {
      console.log("Problem verifying Chat protobuf payload");
    }
    var chatmessage = Chat.create(payload);
    var serializedChat = Chat.encode(chatmessage).finish();
    // console.log("chatPbSerialized", Chat.decode(serializedChat));

    // Stuff Chat object into Message object
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
    // console.log("Serialized Message: ", Message.decode(serializedMessage));

    // Generate ed25519 keypair from BIP39 mnemonic
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

      if(err) {
        console.log('Error generating keypair from seed');
      }

      // Sign the serialized message
      var signature = nacl.sign.detached(serializedMessage, keypair._key);

      // Create envelope
      var envelope_payload = {
        message: messageMessage,
        pubkey: crypto2.keys.marshalPublicKey(keypair.public),
        signature: signature
      };

      if(Envelope.verify(envelope_payload)) {
        console.log("Problem verifying Envelope protobuf payload");
      }
      var envelopeMessage = Envelope.create(envelope_payload);
      var serializedEnvelope = Envelope.encode(envelopeMessage).finish();
      // console.log("Serialized Envelope:", serializedEnvelope.length, serializedEnvelope);

      // Convert recipient's pubkey
      //var recipientPublicKeyB64 = "CAESIKprq8wuWnTgNxi+8GhcgPR/ZMMlliWOX1NUTXAkmEw7";
      var pubkeyBytes = Buffer.from(identity_key, 'base64');
      console.log("recipientPublicKey:", pubkeyBytes.length, pubkeyBytes);
      var unmarshPubkey = crypto2.keys.unmarshalPublicKey(pubkeyBytes);

      var encoded_ciphertext = get_encoded_ciphertext(serializedEnvelope, unmarshPubkey);

      cb(encoded_ciphertext);

    });
  };

  // Retrieve a listing json file for recipient to get identity key
  function cb_identitykey(error, response, body) {
    if (!error && response.statusCode === 200) {

      identity_key = body.listing.vendorID.pubkeys.identity;
      console.log("Identity Key:", identity_key);

      // Load Messages proto
      var jsonDescriptor = require("./message.json");
      constructMessage(jsonDescriptor);
    }
  }

  // Retrieve listings.json for the target recipient
  var cb_listings = (error, response, body) => {
    if (!error && response.statusCode === 200) {
        var slug = body[0].slug;
        request({
          url: domain+"/listings/"+slug+".json",
          json:true
        }, cb_identitykey);
    }
  };

  // Get pubkey associated with peerID
  // 1. Get listings.json
  // 2. If listings then grab the first one and get the pubkey
  var domain = "https://gateway.ob1.io/ipns/"+peerid;
  var url = domain+"/listings.json";
  request({ url: url, json: true }, cb_listings);

}

/***************
/* Call these methods from the browser
****************/
window.getSubKey = (peerID) => {
  subscription_key = generateSubscriptionKey(peerID);
  return subscription_key;
}

window.sendMessage = function sendMessage(peerid, message) {

  generateMessageEnvelope(peerid, message, (envelope) => {
    console.log(ws);
    if(!ws) {
      ws = new WebSocket(relay_server);
      ws.onopen = () => {
        // Send Auth
        ws.send('{"UserID":"'+peerid+'","SubscriptionKey":"'+subscription_key+'"}');
        ws.send('{"recipient":"'+peerid+'","encryptedMessage":"'+envelope+'"}')
      };
    } else {
      // Send Message
      ws.send('{"recipient":"'+peerid+'","encryptedMessage":"'+envelope+'"}')
    }

    ws.onmessage = (data) => {
      console.log(data);
    };

  });
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
      cb({
        "mnemonic": mnemonic,
        "peerid": key._idB58String
      });
    });

  });
}
