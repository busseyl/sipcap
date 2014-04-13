// Base Requires
var util = require('util');
var fs = require('fs');

// Logger function
function log(msg) {
    //console.log(new Date().toJSON() + ': ' + msg.toString());
}

/**
 * Redis
 */
var redis = require('redis');
var client = redis.createClient();

client.on('error', function(err) {
    log('Redis ERROR: ' + err);
});

/**
 * ElasticSearch
 */
//var elasticsearch = require('elasticsearch');
//var client = new elasticsearch.Client({
//    host: '127.0.0.1:9200',
//    apiVersion: '1.0'
//});

// UDP
//var net = require('dgram');
//var sb = require('stream-buffers');

// UDP Stream Buffer
//var stream = new sb.ReadableStreamBuffer();

// SIP
var sip = require('sip');

// Pcap Parser
var pcap = require('pcap');
var pcapp = require('pcap-parser');
//var parser = pcapp.parse(stream);
parser = pcap.createSession('eth0', 'udp port 5060');

// Print all devices, currently listening device prefixed with an asterisk
console.log("All devices:");
parser.findalldevs().forEach(function (dev) {
    if (parser.device_name === dev.name) {
        util.print("* ");
    }
    util.print(dev.name + " ");
    if (dev.addresses.length > 0) {
        dev.addresses.forEach(function (address) {
            util.print(address.addr + "/" + address.netmask);
        });
        util.print("\n");
    } else {
        util.print("no address\n");
    }
});

parser.on('packet', function(packet) {
    var pcap_decode = pcap.decode.packet(packet);
    var sip_packet  = sip.parse(pcap_decode.link.ip.udp.data.toString());

    if(typeof(sip_packet) == 'undefined') {
        log('Invalid SIP packet');
        return false;
    }
    //sip_packet["@timestamp"] = now;
    //pcap_decode["@timestamp"] = now;

    // Structure the JSON
    pcap_decode.link.ip.udp.data = undefined;
    sip_packet.link = pcap_decode.link;
    sip_packet.pcap_header = pcap_decode.pcap_header;

    var sip_h = sip_packet.headers;
    var ruri = false;
    if(sip_packet['method']) {
        ruri = sip_packet['method'] + ' ' + sip_packet['uri'];
    } else if(sip_packet['status']) {
        ruri = sip_packet['status'] + ' ' + sip_packet['reason'];
    }

    if(ruri) {
        log('[' + sip_h['call-id'] + '] ' + ruri);

        // Push to Redis
        client.lpush('sipcap', JSON.stringify(sip_packet), function(err, res) {
//            log(util.inspect(res));
        });

//        client.lpush('sipcap', JSON.stringify(pcap_decode), function(err, reply) {
//            log(util.inspect(err));
//        });

        // Push to elasticsearch
//        client.index({
//            index: 'pcap',
//            type: 'packet',
//            body: pcap_decode,
//            timestamp: now
//        }, function(err, res) {
//            log(util.inspect(err));
//        });

//        client.index({
//            index: 'sip',
//            type: 'sipcap',
//            body: sip_packet,
//            timestamp: now
//        }, function(err, res) {
//            log(util.inspect(err));
//        });
    } else {
        log('Unknown SIP packet');
        return false;
    }
});

// Open a UDP socket to listen on
//var port = 9000;
//var server = net.createSocket('udp4');

//server.addListener('message', function(msg, rinfo) {
//    log('Remote machine : ' + util.inspect(rinfo));
//    log('Message        : ' + util.inspect(msg));

    // Stream the input to the stream buffer
//    stream.put(msg);
//});
//server.bind(port);
