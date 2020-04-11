(function (global, factory) {
	typeof exports === 'object' && typeof module !== 'undefined' ? module.exports = factory() :
	typeof define === 'function' && define.amd ? define(factory) :
	(global = global || self, global.Dugon = factory());
}(this, (function () { 'use strict';

	function createCommonjsModule(fn, module) {
		return module = { exports: {} }, fn(module, module.exports), module.exports;
	}

	var grammar_1 = createCommonjsModule(function (module) {
	var grammar = module.exports = {
	  v: [{
	    name: 'version',
	    reg: /^(\d*)$/
	  }],
	  o: [{
	    // o=- 20518 0 IN IP4 203.0.113.1
	    // NB: sessionId will be a String in most cases because it is huge
	    name: 'origin',
	    reg: /^(\S*) (\d*) (\d*) (\S*) IP(\d) (\S*)/,
	    names: ['username', 'sessionId', 'sessionVersion', 'netType', 'ipVer', 'address'],
	    format: '%s %s %d %s IP%d %s'
	  }],
	  // default parsing of these only (though some of these feel outdated)
	  s: [{ name: 'name' }],
	  i: [{ name: 'description' }],
	  u: [{ name: 'uri' }],
	  e: [{ name: 'email' }],
	  p: [{ name: 'phone' }],
	  z: [{ name: 'timezones' }], // TODO: this one can actually be parsed properly...
	  r: [{ name: 'repeats' }],   // TODO: this one can also be parsed properly
	  // k: [{}], // outdated thing ignored
	  t: [{
	    // t=0 0
	    name: 'timing',
	    reg: /^(\d*) (\d*)/,
	    names: ['start', 'stop'],
	    format: '%d %d'
	  }],
	  c: [{
	    // c=IN IP4 10.47.197.26
	    name: 'connection',
	    reg: /^IN IP(\d) (\S*)/,
	    names: ['version', 'ip'],
	    format: 'IN IP%d %s'
	  }],
	  b: [{
	    // b=AS:4000
	    push: 'bandwidth',
	    reg: /^(TIAS|AS|CT|RR|RS):(\d*)/,
	    names: ['type', 'limit'],
	    format: '%s:%s'
	  }],
	  m: [{
	    // m=video 51744 RTP/AVP 126 97 98 34 31
	    // NB: special - pushes to session
	    // TODO: rtp/fmtp should be filtered by the payloads found here?
	    reg: /^(\w*) (\d*) ([\w/]*)(?: (.*))?/,
	    names: ['type', 'port', 'protocol', 'payloads'],
	    format: '%s %d %s %s'
	  }],
	  a: [
	    {
	      // a=rtpmap:110 opus/48000/2
	      push: 'rtp',
	      reg: /^rtpmap:(\d*) ([\w\-.]*)(?:\s*\/(\d*)(?:\s*\/(\S*))?)?/,
	      names: ['payload', 'codec', 'rate', 'encoding'],
	      format: function (o) {
	        return (o.encoding)
	          ? 'rtpmap:%d %s/%s/%s'
	          : o.rate
	            ? 'rtpmap:%d %s/%s'
	            : 'rtpmap:%d %s';
	      }
	    },
	    {
	      // a=fmtp:108 profile-level-id=24;object=23;bitrate=64000
	      // a=fmtp:111 minptime=10; useinbandfec=1
	      push: 'fmtp',
	      reg: /^fmtp:(\d*) ([\S| ]*)/,
	      names: ['payload', 'config'],
	      format: 'fmtp:%d %s'
	    },
	    {
	      // a=control:streamid=0
	      name: 'control',
	      reg: /^control:(.*)/,
	      format: 'control:%s'
	    },
	    {
	      // a=rtcp:65179 IN IP4 193.84.77.194
	      name: 'rtcp',
	      reg: /^rtcp:(\d*)(?: (\S*) IP(\d) (\S*))?/,
	      names: ['port', 'netType', 'ipVer', 'address'],
	      format: function (o) {
	        return (o.address != null)
	          ? 'rtcp:%d %s IP%d %s'
	          : 'rtcp:%d';
	      }
	    },
	    {
	      // a=rtcp-fb:98 trr-int 100
	      push: 'rtcpFbTrrInt',
	      reg: /^rtcp-fb:(\*|\d*) trr-int (\d*)/,
	      names: ['payload', 'value'],
	      format: 'rtcp-fb:%d trr-int %d'
	    },
	    {
	      // a=rtcp-fb:98 nack rpsi
	      push: 'rtcpFb',
	      reg: /^rtcp-fb:(\*|\d*) ([\w-_]*)(?: ([\w-_]*))?/,
	      names: ['payload', 'type', 'subtype'],
	      format: function (o) {
	        return (o.subtype != null)
	          ? 'rtcp-fb:%s %s %s'
	          : 'rtcp-fb:%s %s';
	      }
	    },
	    {
	      // a=extmap:2 urn:ietf:params:rtp-hdrext:toffset
	      // a=extmap:1/recvonly URI-gps-string
	      // a=extmap:3 urn:ietf:params:rtp-hdrext:encrypt urn:ietf:params:rtp-hdrext:smpte-tc 25@600/24
	      push: 'ext',
	      reg: /^extmap:(\d+)(?:\/(\w+))?(?: (urn:ietf:params:rtp-hdrext:encrypt))? (\S*)(?: (\S*))?/,
	      names: ['value', 'direction', 'encrypt-uri', 'uri', 'config'],
	      format: function (o) {
	        return (
	          'extmap:%d' +
	          (o.direction ? '/%s' : '%v') +
	          (o['encrypt-uri'] ? ' %s' : '%v') +
	          ' %s' +
	          (o.config ? ' %s' : '')
	        );
	      }
	    },
	    {
	      // a=extmap-allow-mixed
	      name: 'extmapAllowMixed',
	      reg: /^(extmap-allow-mixed)/
	    },
	    {
	      // a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20|1:32
	      push: 'crypto',
	      reg: /^crypto:(\d*) ([\w_]*) (\S*)(?: (\S*))?/,
	      names: ['id', 'suite', 'config', 'sessionConfig'],
	      format: function (o) {
	        return (o.sessionConfig != null)
	          ? 'crypto:%d %s %s %s'
	          : 'crypto:%d %s %s';
	      }
	    },
	    {
	      // a=setup:actpass
	      name: 'setup',
	      reg: /^setup:(\w*)/,
	      format: 'setup:%s'
	    },
	    {
	      // a=connection:new
	      name: 'connectionType',
	      reg: /^connection:(new|existing)/,
	      format: 'connection:%s'
	    },
	    {
	      // a=mid:1
	      name: 'mid',
	      reg: /^mid:([^\s]*)/,
	      format: 'mid:%s'
	    },
	    {
	      // a=msid:0c8b064d-d807-43b4-b434-f92a889d8587 98178685-d409-46e0-8e16-7ef0db0db64a
	      name: 'msid',
	      reg: /^msid:(.*)/,
	      format: 'msid:%s'
	    },
	    {
	      // a=ptime:20
	      name: 'ptime',
	      reg: /^ptime:(\d*(?:\.\d*)*)/,
	      format: 'ptime:%d'
	    },
	    {
	      // a=maxptime:60
	      name: 'maxptime',
	      reg: /^maxptime:(\d*(?:\.\d*)*)/,
	      format: 'maxptime:%d'
	    },
	    {
	      // a=sendrecv
	      name: 'direction',
	      reg: /^(sendrecv|recvonly|sendonly|inactive)/
	    },
	    {
	      // a=ice-lite
	      name: 'icelite',
	      reg: /^(ice-lite)/
	    },
	    {
	      // a=ice-ufrag:F7gI
	      name: 'iceUfrag',
	      reg: /^ice-ufrag:(\S*)/,
	      format: 'ice-ufrag:%s'
	    },
	    {
	      // a=ice-pwd:x9cml/YzichV2+XlhiMu8g
	      name: 'icePwd',
	      reg: /^ice-pwd:(\S*)/,
	      format: 'ice-pwd:%s'
	    },
	    {
	      // a=fingerprint:SHA-1 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33
	      name: 'fingerprint',
	      reg: /^fingerprint:(\S*) (\S*)/,
	      names: ['type', 'hash'],
	      format: 'fingerprint:%s %s'
	    },
	    {
	      // a=candidate:0 1 UDP 2113667327 203.0.113.1 54400 typ host
	      // a=candidate:1162875081 1 udp 2113937151 192.168.34.75 60017 typ host generation 0 network-id 3 network-cost 10
	      // a=candidate:3289912957 2 udp 1845501695 193.84.77.194 60017 typ srflx raddr 192.168.34.75 rport 60017 generation 0 network-id 3 network-cost 10
	      // a=candidate:229815620 1 tcp 1518280447 192.168.150.19 60017 typ host tcptype active generation 0 network-id 3 network-cost 10
	      // a=candidate:3289912957 2 tcp 1845501695 193.84.77.194 60017 typ srflx raddr 192.168.34.75 rport 60017 tcptype passive generation 0 network-id 3 network-cost 10
	      push:'candidates',
	      reg: /^candidate:(\S*) (\d*) (\S*) (\d*) (\S*) (\d*) typ (\S*)(?: raddr (\S*) rport (\d*))?(?: tcptype (\S*))?(?: generation (\d*))?(?: network-id (\d*))?(?: network-cost (\d*))?/,
	      names: ['foundation', 'component', 'transport', 'priority', 'ip', 'port', 'type', 'raddr', 'rport', 'tcptype', 'generation', 'network-id', 'network-cost'],
	      format: function (o) {
	        var str = 'candidate:%s %d %s %d %s %d typ %s';

	        str += (o.raddr != null) ? ' raddr %s rport %d' : '%v%v';

	        // NB: candidate has three optional chunks, so %void middles one if it's missing
	        str += (o.tcptype != null) ? ' tcptype %s' : '%v';

	        if (o.generation != null) {
	          str += ' generation %d';
	        }

	        str += (o['network-id'] != null) ? ' network-id %d' : '%v';
	        str += (o['network-cost'] != null) ? ' network-cost %d' : '%v';
	        return str;
	      }
	    },
	    {
	      // a=end-of-candidates (keep after the candidates line for readability)
	      name: 'endOfCandidates',
	      reg: /^(end-of-candidates)/
	    },
	    {
	      // a=remote-candidates:1 203.0.113.1 54400 2 203.0.113.1 54401 ...
	      name: 'remoteCandidates',
	      reg: /^remote-candidates:(.*)/,
	      format: 'remote-candidates:%s'
	    },
	    {
	      // a=ice-options:google-ice
	      name: 'iceOptions',
	      reg: /^ice-options:(\S*)/,
	      format: 'ice-options:%s'
	    },
	    {
	      // a=ssrc:2566107569 cname:t9YU8M1UxTF8Y1A1
	      push: 'ssrcs',
	      reg: /^ssrc:(\d*) ([\w_-]*)(?::(.*))?/,
	      names: ['id', 'attribute', 'value'],
	      format: function (o) {
	        var str = 'ssrc:%d';
	        if (o.attribute != null) {
	          str += ' %s';
	          if (o.value != null) {
	            str += ':%s';
	          }
	        }
	        return str;
	      }
	    },
	    {
	      // a=ssrc-group:FEC 1 2
	      // a=ssrc-group:FEC-FR 3004364195 1080772241
	      push: 'ssrcGroups',
	      // token-char = %x21 / %x23-27 / %x2A-2B / %x2D-2E / %x30-39 / %x41-5A / %x5E-7E
	      reg: /^ssrc-group:([\x21\x23\x24\x25\x26\x27\x2A\x2B\x2D\x2E\w]*) (.*)/,
	      names: ['semantics', 'ssrcs'],
	      format: 'ssrc-group:%s %s'
	    },
	    {
	      // a=msid-semantic: WMS Jvlam5X3SX1OP6pn20zWogvaKJz5Hjf9OnlV
	      name: 'msidSemantic',
	      reg: /^msid-semantic:\s?(\w*) (\S*)/,
	      names: ['semantic', 'token'],
	      format: 'msid-semantic: %s %s' // space after ':' is not accidental
	    },
	    {
	      // a=group:BUNDLE audio video
	      push: 'groups',
	      reg: /^group:(\w*) (.*)/,
	      names: ['type', 'mids'],
	      format: 'group:%s %s'
	    },
	    {
	      // a=rtcp-mux
	      name: 'rtcpMux',
	      reg: /^(rtcp-mux)/
	    },
	    {
	      // a=rtcp-rsize
	      name: 'rtcpRsize',
	      reg: /^(rtcp-rsize)/
	    },
	    {
	      // a=sctpmap:5000 webrtc-datachannel 1024
	      name: 'sctpmap',
	      reg: /^sctpmap:([\w_/]*) (\S*)(?: (\S*))?/,
	      names: ['sctpmapNumber', 'app', 'maxMessageSize'],
	      format: function (o) {
	        return (o.maxMessageSize != null)
	          ? 'sctpmap:%s %s %s'
	          : 'sctpmap:%s %s';
	      }
	    },
	    {
	      // a=x-google-flag:conference
	      name: 'xGoogleFlag',
	      reg: /^x-google-flag:([^\s]*)/,
	      format: 'x-google-flag:%s'
	    },
	    {
	      // a=rid:1 send max-width=1280;max-height=720;max-fps=30;depend=0
	      push: 'rids',
	      reg: /^rid:([\d\w]+) (\w+)(?: ([\S| ]*))?/,
	      names: ['id', 'direction', 'params'],
	      format: function (o) {
	        return (o.params) ? 'rid:%s %s %s' : 'rid:%s %s';
	      }
	    },
	    {
	      // a=imageattr:97 send [x=800,y=640,sar=1.1,q=0.6] [x=480,y=320] recv [x=330,y=250]
	      // a=imageattr:* send [x=800,y=640] recv *
	      // a=imageattr:100 recv [x=320,y=240]
	      push: 'imageattrs',
	      reg: new RegExp(
	        // a=imageattr:97
	        '^imageattr:(\\d+|\\*)' +
	        // send [x=800,y=640,sar=1.1,q=0.6] [x=480,y=320]
	        '[\\s\\t]+(send|recv)[\\s\\t]+(\\*|\\[\\S+\\](?:[\\s\\t]+\\[\\S+\\])*)' +
	        // recv [x=330,y=250]
	        '(?:[\\s\\t]+(recv|send)[\\s\\t]+(\\*|\\[\\S+\\](?:[\\s\\t]+\\[\\S+\\])*))?'
	      ),
	      names: ['pt', 'dir1', 'attrs1', 'dir2', 'attrs2'],
	      format: function (o) {
	        return 'imageattr:%s %s %s' + (o.dir2 ? ' %s %s' : '');
	      }
	    },
	    {
	      // a=simulcast:send 1,2,3;~4,~5 recv 6;~7,~8
	      // a=simulcast:recv 1;4,5 send 6;7
	      name: 'simulcast',
	      reg: new RegExp(
	        // a=simulcast:
	        '^simulcast:' +
	        // send 1,2,3;~4,~5
	        '(send|recv) ([a-zA-Z0-9\\-_~;,]+)' +
	        // space + recv 6;~7,~8
	        '(?:\\s?(send|recv) ([a-zA-Z0-9\\-_~;,]+))?' +
	        // end
	        '$'
	      ),
	      names: ['dir1', 'list1', 'dir2', 'list2'],
	      format: function (o) {
	        return 'simulcast:%s %s' + (o.dir2 ? ' %s %s' : '');
	      }
	    },
	    {
	      // old simulcast draft 03 (implemented by Firefox)
	      //   https://tools.ietf.org/html/draft-ietf-mmusic-sdp-simulcast-03
	      // a=simulcast: recv pt=97;98 send pt=97
	      // a=simulcast: send rid=5;6;7 paused=6,7
	      name: 'simulcast_03',
	      reg: /^simulcast:[\s\t]+([\S+\s\t]+)$/,
	      names: ['value'],
	      format: 'simulcast: %s'
	    },
	    {
	      // a=framerate:25
	      // a=framerate:29.97
	      name: 'framerate',
	      reg: /^framerate:(\d+(?:$|\.\d+))/,
	      format: 'framerate:%s'
	    },
	    {
	      // RFC4570
	      // a=source-filter: incl IN IP4 239.5.2.31 10.1.15.5
	      name: 'sourceFilter',
	      reg: /^source-filter: *(excl|incl) (\S*) (IP4|IP6|\*) (\S*) (.*)/,
	      names: ['filterMode', 'netType', 'addressTypes', 'destAddress', 'srcList'],
	      format: 'source-filter: %s %s %s %s %s'
	    },
	    {
	      // a=bundle-only
	      name: 'bundleOnly',
	      reg: /^(bundle-only)/
	    },
	    {
	      // a=label:1
	      name: 'label',
	      reg: /^label:(.+)/,
	      format: 'label:%s'
	    },
	    {
	      // RFC version 26 for SCTP over DTLS
	      // https://tools.ietf.org/html/draft-ietf-mmusic-sctp-sdp-26#section-5
	      name: 'sctpPort',
	      reg: /^sctp-port:(\d+)$/,
	      format: 'sctp-port:%s'
	    },
	    {
	      // RFC version 26 for SCTP over DTLS
	      // https://tools.ietf.org/html/draft-ietf-mmusic-sctp-sdp-26#section-6
	      name: 'maxMessageSize',
	      reg: /^max-message-size:(\d+)$/,
	      format: 'max-message-size:%s'
	    },
	    {
	      // RFC7273
	      // a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:37
	      push:'tsRefClocks',
	      reg: /^ts-refclk:([^\s=]*)(?:=(\S*))?/,
	      names: ['clksrc', 'clksrcExt'],
	      format: function (o) {
	        return 'ts-refclk:%s' + (o.clksrcExt != null ? '=%s' : '');
	      }
	    },
	    {
	      // RFC7273
	      // a=mediaclk:direct=963214424
	      name:'mediaClk',
	      reg: /^mediaclk:(?:id=(\S*))? *([^\s=]*)(?:=(\S*))?(?: *rate=(\d+)\/(\d+))?/,
	      names: ['id', 'mediaClockName', 'mediaClockValue', 'rateNumerator', 'rateDenominator'],
	      format: function (o) {
	        var str = 'mediaclk:';
	        str += (o.id != null ? 'id=%s %s' : '%v%s');
	        str += (o.mediaClockValue != null ? '=%s' : '');
	        str += (o.rateNumerator != null ? ' rate=%s' : '');
	        str += (o.rateDenominator != null ? '/%s' : '');
	        return str;
	      }
	    },
	    {
	      // a=keywds:keywords
	      name: 'keywords',
	      reg: /^keywds:(.+)$/,
	      format: 'keywds:%s'
	    },
	    {
	      // a=content:main
	      name: 'content',
	      reg: /^content:(.+)/,
	      format: 'content:%s'
	    },
	    // BFCP https://tools.ietf.org/html/rfc4583
	    {
	      // a=floorctrl:c-s
	      name: 'bfcpFloorCtrl',
	      reg: /^floorctrl:(c-only|s-only|c-s)/,
	      format: 'floorctrl:%s'
	    },
	    {
	      // a=confid:1
	      name: 'bfcpConfId',
	      reg: /^confid:(\d+)/,
	      format: 'confid:%s'
	    },
	    {
	      // a=userid:1
	      name: 'bfcpUserId',
	      reg: /^userid:(\d+)/,
	      format: 'userid:%s'
	    },
	    {
	      // a=floorid:1
	      name: 'bfcpFloorId',
	      reg: /^floorid:(.+) (?:m-stream|mstrm):(.+)/,
	      names: ['id', 'mStream'],
	      format: 'floorid:%s mstrm:%s'
	    },
	    {
	      // any a= that we don't understand is kept verbatim on media.invalid
	      push: 'invalid',
	      names: ['value']
	    }
	  ]
	};

	// set sensible defaults to avoid polluting the grammar with boring details
	Object.keys(grammar).forEach(function (key) {
	  var objs = grammar[key];
	  objs.forEach(function (obj) {
	    if (!obj.reg) {
	      obj.reg = /(.*)/;
	    }
	    if (!obj.format) {
	      obj.format = '%s';
	    }
	  });
	});
	});
	var grammar_2 = grammar_1.v;
	var grammar_3 = grammar_1.o;
	var grammar_4 = grammar_1.s;
	var grammar_5 = grammar_1.i;
	var grammar_6 = grammar_1.u;
	var grammar_7 = grammar_1.e;
	var grammar_8 = grammar_1.p;
	var grammar_9 = grammar_1.z;
	var grammar_10 = grammar_1.r;
	var grammar_11 = grammar_1.t;
	var grammar_12 = grammar_1.c;
	var grammar_13 = grammar_1.b;
	var grammar_14 = grammar_1.m;
	var grammar_15 = grammar_1.a;

	var parser = createCommonjsModule(function (module, exports) {
	var toIntIfInt = function (v) {
	  return String(Number(v)) === v ? Number(v) : v;
	};

	var attachProperties = function (match, location, names, rawName) {
	  if (rawName && !names) {
	    location[rawName] = toIntIfInt(match[1]);
	  }
	  else {
	    for (var i = 0; i < names.length; i += 1) {
	      if (match[i+1] != null) {
	        location[names[i]] = toIntIfInt(match[i+1]);
	      }
	    }
	  }
	};

	var parseReg = function (obj, location, content) {
	  var needsBlank = obj.name && obj.names;
	  if (obj.push && !location[obj.push]) {
	    location[obj.push] = [];
	  }
	  else if (needsBlank && !location[obj.name]) {
	    location[obj.name] = {};
	  }
	  var keyLocation = obj.push ?
	    {} :  // blank object that will be pushed
	    needsBlank ? location[obj.name] : location; // otherwise, named location or root

	  attachProperties(content.match(obj.reg), keyLocation, obj.names, obj.name);

	  if (obj.push) {
	    location[obj.push].push(keyLocation);
	  }
	};


	var validLine = RegExp.prototype.test.bind(/^([a-z])=(.*)/);

	exports.parse = function (sdp) {
	  var session = {}
	    , media = []
	    , location = session; // points at where properties go under (one of the above)

	  // parse lines we understand
	  sdp.split(/(\r\n|\r|\n)/).filter(validLine).forEach(function (l) {
	    var type = l[0];
	    var content = l.slice(2);
	    if (type === 'm') {
	      media.push({rtp: [], fmtp: []});
	      location = media[media.length-1]; // point at latest media line
	    }

	    for (var j = 0; j < (grammar_1[type] || []).length; j += 1) {
	      var obj = grammar_1[type][j];
	      if (obj.reg.test(content)) {
	        return parseReg(obj, location, content);
	      }
	    }
	  });

	  session.media = media; // link it up
	  return session;
	};

	var paramReducer = function (acc, expr) {
	  var s = expr.split(/=(.+)/, 2);
	  if (s.length === 2) {
	    acc[s[0]] = toIntIfInt(s[1]);
	  } else if (s.length === 1 && expr.length > 1) {
	    acc[s[0]] = undefined;
	  }
	  return acc;
	};

	exports.parseParams = function (str) {
	  return str.split(/;\s?/).reduce(paramReducer, {});
	};

	// For backward compatibility - alias will be removed in 3.0.0
	exports.parseFmtpConfig = exports.parseParams;

	exports.parsePayloads = function (str) {
	  return str.toString().split(' ').map(Number);
	};

	exports.parseRemoteCandidates = function (str) {
	  var candidates = [];
	  var parts = str.split(' ').map(toIntIfInt);
	  for (var i = 0; i < parts.length; i += 3) {
	    candidates.push({
	      component: parts[i],
	      ip: parts[i + 1],
	      port: parts[i + 2]
	    });
	  }
	  return candidates;
	};

	exports.parseImageAttributes = function (str) {
	  return str.split(' ').map(function (item) {
	    return item.substring(1, item.length-1).split(',').reduce(paramReducer, {});
	  });
	};

	exports.parseSimulcastStreamList = function (str) {
	  return str.split(';').map(function (stream) {
	    return stream.split(',').map(function (format) {
	      var scid, paused = false;

	      if (format[0] !== '~') {
	        scid = toIntIfInt(format);
	      } else {
	        scid = toIntIfInt(format.substring(1, format.length));
	        paused = true;
	      }

	      return {
	        scid: scid,
	        paused: paused
	      };
	    });
	  });
	};
	});
	var parser_1 = parser.parse;
	var parser_2 = parser.parseParams;
	var parser_3 = parser.parseFmtpConfig;
	var parser_4 = parser.parsePayloads;
	var parser_5 = parser.parseRemoteCandidates;
	var parser_6 = parser.parseImageAttributes;
	var parser_7 = parser.parseSimulcastStreamList;

	// customized util.format - discards excess arguments and can void middle ones
	var formatRegExp = /%[sdv%]/g;
	var format = function (formatStr) {
	  var i = 1;
	  var args = arguments;
	  var len = args.length;
	  return formatStr.replace(formatRegExp, function (x) {
	    if (i >= len) {
	      return x; // missing argument
	    }
	    var arg = args[i];
	    i += 1;
	    switch (x) {
	    case '%%':
	      return '%';
	    case '%s':
	      return String(arg);
	    case '%d':
	      return Number(arg);
	    case '%v':
	      return '';
	    }
	  });
	  // NB: we discard excess arguments - they are typically undefined from makeLine
	};

	var makeLine = function (type, obj, location) {
	  var str = obj.format instanceof Function ?
	    (obj.format(obj.push ? location : location[obj.name])) :
	    obj.format;

	  var args = [type + '=' + str];
	  if (obj.names) {
	    for (var i = 0; i < obj.names.length; i += 1) {
	      var n = obj.names[i];
	      if (obj.name) {
	        args.push(location[obj.name][n]);
	      }
	      else { // for mLine and push attributes
	        args.push(location[obj.names[i]]);
	      }
	    }
	  }
	  else {
	    args.push(location[obj.name]);
	  }
	  return format.apply(null, args);
	};

	// RFC specified order
	// TODO: extend this with all the rest
	var defaultOuterOrder = [
	  'v', 'o', 's', 'i',
	  'u', 'e', 'p', 'c',
	  'b', 't', 'r', 'z', 'a'
	];
	var defaultInnerOrder = ['i', 'c', 'b', 'a'];


	var writer = function (session, opts) {
	  opts = opts || {};
	  // ensure certain properties exist
	  if (session.version == null) {
	    session.version = 0; // 'v=0' must be there (only defined version atm)
	  }
	  if (session.name == null) {
	    session.name = ' '; // 's= ' must be there if no meaningful name set
	  }
	  session.media.forEach(function (mLine) {
	    if (mLine.payloads == null) {
	      mLine.payloads = '';
	    }
	  });

	  var outerOrder = opts.outerOrder || defaultOuterOrder;
	  var innerOrder = opts.innerOrder || defaultInnerOrder;
	  var sdp = [];

	  // loop through outerOrder for matching properties on session
	  outerOrder.forEach(function (type) {
	    grammar_1[type].forEach(function (obj) {
	      if (obj.name in session && session[obj.name] != null) {
	        sdp.push(makeLine(type, obj, session));
	      }
	      else if (obj.push in session && session[obj.push] != null) {
	        session[obj.push].forEach(function (el) {
	          sdp.push(makeLine(type, obj, el));
	        });
	      }
	    });
	  });

	  // then for each media line, follow the innerOrder
	  session.media.forEach(function (mLine) {
	    sdp.push(makeLine('m', grammar_1.m[0], mLine));

	    innerOrder.forEach(function (type) {
	      grammar_1[type].forEach(function (obj) {
	        if (obj.name in mLine && mLine[obj.name] != null) {
	          sdp.push(makeLine(type, obj, mLine));
	        }
	        else if (obj.push in mLine && mLine[obj.push] != null) {
	          mLine[obj.push].forEach(function (el) {
	            sdp.push(makeLine(type, obj, el));
	          });
	        }
	      });
	    });
	  });

	  return sdp.join('\r\n') + '\r\n';
	};

	var write = writer;
	var parse = parser.parse;
	var parseParams = parser.parseParams;
	var parseFmtpConfig = parser.parseFmtpConfig; // Alias of parseParams().
	var parsePayloads = parser.parsePayloads;
	var parseRemoteCandidates = parser.parseRemoteCandidates;
	var parseImageAttributes = parser.parseImageAttributes;
	var parseSimulcastStreamList = parser.parseSimulcastStreamList;

	var lib = {
		write: write,
		parse: parse,
		parseParams: parseParams,
		parseFmtpConfig: parseFmtpConfig,
		parsePayloads: parsePayloads,
		parseRemoteCandidates: parseRemoteCandidates,
		parseImageAttributes: parseImageAttributes,
		parseSimulcastStreamList: parseSimulcastStreamList
	};

	function randomInitId(length) {
	  let randomNum = 0;
	  while (randomNum < 0.1) {
	    randomNum = Math.random();
	  }
	  return parseInt(randomNum * Math.pow(10, length))
	}

	class TrackSdp {
	  constructor(codec, payloads, type, direction) {
	    this.codec = codec;
	    this.payloads = payloads;

	    this.type = type;

	    this.direction = direction;
	  }

	  generate(isActive, mid, setup, iceUfrag, icePwd, candidates) {
	    const template = {};

	    //audio
	    const audioRtp = [
	      {
	        "payload": 111,
	        "codec": "opus",
	        "rate": 48000,
	        "encoding": 2
	      }
	    ];

	    const audioFtmp = [
	      {
	        "payload": 111,
	        "config": "stereo=1;usedtx=1"
	      }

	    ];

	    const audioRtcpFb = [
	      {
	        "payload": 111,
	        "type": "transport-cc",
	        "subtype": ""
	      }
	    ];

	    const audioExt = [
	      {
	        "value": 4,
	        "uri": "urn:ietf:params:rtp-hdrext:sdes:mid"
	      },
	      {
	        "value": 2,
	        "uri": "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"
	      },
	      {
	        "value": 3,
	        "uri": "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"
	      },
	      {
	        "value": 1,
	        "uri": "urn:ietf:params:rtp-hdrext:ssrc-audio-level"
	      }
	    ];

	    //video
	    const videoRtp = [
	      {
	        "payload": 96,
	        "codec": "VP8",
	        "rate": 90000
	      },
	      {
	        "payload": 97,
	        "codec": "rtx",
	        "rate": 90000
	      }
	    ];

	    const videoFmtp = [
	      {
	        "payload": 96,
	        "config": "x-google-start-bitrate=1000"
	      },
	      {
	        "payload": 97,
	        "config": "apt=96"
	      }
	    ];

	    const videoRtcpFb = [
	      {
	        "payload": 96,
	        "type": "transport-cc",
	        "subtype": ""
	      },
	      {
	        "payload": 96,
	        "type": "ccm",
	        "subtype": "fir"
	      },
	      {
	        "payload": 96,
	        "type": "nack",
	        "subtype": ""
	      },
	      {
	        "payload": 96,
	        "type": "nack",
	        "subtype": "pli"
	      }
	    ];

	    const videoExt = [
	      {
	        "value": 4,
	        "uri": "urn:ietf:params:rtp-hdrext:sdes:mid"
	      },
	      {
	        "value": 5,
	        "uri": "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id"
	      },
	      {
	        "value": 6,
	        "uri": "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id"
	      },
	      {
	        "value": 2,
	        "uri": "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"
	      },
	      {
	        "value": 3,
	        "uri": "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"
	      },
	      {
	        "value": 8,
	        "uri": "http://tools.ietf.org/html/draft-ietf-avtext-framemarking-07"
	      },
	      {
	        "value": 13,
	        "uri": "urn:3gpp:video-orientation"
	      },
	      {
	        "value": 14,
	        "uri": "urn:ietf:params:rtp-hdrext:toffset"
	      }
	    ];

	    let ext;
	    if (this.type === 'audio') {
	      template['rtp'] = audioRtp;
	      template['fmtp'] = audioFtmp;
	      template['rtcpFb'] = audioRtcpFb;
	      ext = audioExt;
	    } else if (this.type === 'video') {
	      template['rtp'] = videoRtp;
	      template['fmtp'] = videoFmtp;
	      template['rtcpFb'] = videoRtcpFb;
	      ext = videoExt;
	    }

	    if (isActive) {
	      template['direction'] = this.direction;
	      template['ext'] = ext;
	      template['port'] = 7;

	    } else {
	      if(mid != '0'){
	        template['port'] = 0;
	      }else{
	        template['port'] = 7;
	      }
	      template['direction'] = 'inactive';
	    }


	    //static
	    template['protocol'] = "UDP/TLS/RTP/SAVPF";
	    template['connection'] = {
	      "version": 4,
	      "ip": "127.0.0.1"
	    };
	    template["endOfCandidates"] = 'end-of-candidates';
	    template["iceOptions"] = "renomination";
	    template["rtcpMux"] = "rtcp-mux";
	    template["rtcpRsize"] = "rtcp-rsize";

	    //dynamic
	    template['type'] = this.type;
	    template['payloads'] = this.payloads;

	    //instant
	    template['setup'] = setup;
	    template['mid'] = mid;
	    template["iceUfrag"] = iceUfrag;
	    template["icePwd"] = icePwd;
	    template["candidates"] = candidates;

	    return template;
	  }
	}


	function pubRemoteSdpGen(senders, remoteICECandidates, remoteICEParameters, remoteDTLSParameters) {
	  const sdpTemplate = {
	    "version": 0,
	    "origin": {
	      "username": "xxx",
	      "sessionId": 10000,
	      "sessionVersion": 2,
	      "netType": "IN",
	      "ipVer": 4,
	      "address": "0.0.0.0"
	    },
	    "name": "-",
	    "timing": {
	      "start": 0,
	      "stop": 0
	    },
	    "msidSemantic": {
	      "semantic": "WMS",
	      "token": "*"
	    },
	    "icelite": "ice-lite",//FIXME: 
	    "groups": [],//BUNDLE
	    "media": [], //medias
	    "fingerprint": {},
	  };

	  let remoteSdpObj = Object.assign({}, sdpTemplate);

	  const fingerprint = {
	    "type": remoteDTLSParameters.fingerprint.algorithm,
	    "hash": remoteDTLSParameters.fingerprint.value
	  };

	  remoteSdpObj.fingerprint = fingerprint;


	  let medias = [];
	  let mids = [];
	  for (let sender of senders) {
	    // console.log(videoTemplate);
	    if (!sender.isStopped || sender.mid === '0') {
	      let trackSdp;
	      if (sender.kind === 'audio') {
	        trackSdp = new TrackSdp('opus', 111, 'audio', 'recvonly');
	        if (sender.available) {
	          mids.push(sender.mid);
	        } else {
	          if (sender.mid === '0') {
	            mids.push(sender.mid);
	          }
	        }

	      } else if (sender.kind === 'video') {
	        trackSdp = new TrackSdp('vp8', '96 97', 'video', 'recvonly');

	        if (sender.available) {
	          mids.push(sender.mid);
	        } else {
	          if (sender.mid === '0') {
	            mids.push(sender.mid);
	          }
	        }
	      }



	      let media = trackSdp.generate(sender.available, sender.mid, remoteDTLSParameters.setup, remoteICEParameters.usernameFragment,
	        remoteICEParameters.password, remoteICECandidates);
	      medias.push(media);
	    }
	  }

	  //todo fix
	  remoteSdpObj.groups = [
	    {
	      "type": "BUNDLE",
	      "mids": mids.join(" ")
	    }
	  ];

	  remoteSdpObj.media = medias;

	  let remoteSdp = new RTCSessionDescription({
	    type: 'answer',
	    sdp: lib.write(remoteSdpObj)
	  });

	  return remoteSdp;
	}

	//TODO: dtx ssrc, group ssrc
	function subRemoteSdpGen(receivers, remoteICECandidates, remoteICEParameters, remoteDTLSParameters) {

	  const sdpTemplate = {
	    "version": 0,
	    "origin": {
	      "username": "mediasoup-client",
	      "sessionId": 10000,
	      "sessionVersion": 1,
	      "netType": "IN",
	      "ipVer": 4,
	      "address": "0.0.0.0"
	    },
	    "name": "-",
	    "timing": {
	      "start": 0,
	      "stop": 0
	    },
	    "icelite": "ice-lite",
	    "fingerprint": {},
	    "msidSemantic": {
	      "semantic": "WMS",
	      "token": "*"
	    },
	    "groups": [
	      {
	        "type": "BUNDLE",
	        "mids": 0
	      }
	    ],
	    "media": []
	  };

	  const audioExt = [
	    {
	      "value": 4,
	      "uri": "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"
	    },
	    {
	      "value": 10,
	      "uri": "urn:ietf:params:rtp-hdrext:ssrc-audio-level"
	    }
	  ];

	  const audioTemplate = {
	    "rtp": [
	      {
	        "payload": 100,
	        "codec": "opus",
	        "rate": 48000,
	        "encoding": 2
	      }
	    ],
	    "fmtp": [
	      {
	        "payload": 100,
	        "config": "minptime=10;useinbandfec=1;sprop-stereo=1;usedtx=1"
	      }
	    ],
	    "type": "audio",
	    "port": 7,
	    "protocol": "UDP/TLS/RTP/SAVPF",
	    "payloads": 100,
	    "connection": {
	      "version": 4,
	      "ip": "127.0.0.1"
	    },
	    "setup": "actpass",
	    "mid": 0,
	    "msid": "",
	    "direction": "",
	    "iceUfrag": "",
	    "icePwd": "",
	    "candidates": [],
	    "endOfCandidates": "end-of-candidates",
	    "iceOptions": "renomination",
	    "ssrcs": [],
	    "rtcpMux": "rtcp-mux",
	    "rtcpRsize": "rtcp-rsize"
	  };

	  const videoExt = [
	    {
	      "value": 4,
	      "uri": "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"
	    },
	    {
	      "value": 5,
	      "uri": "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"
	    },
	    {
	      "value": 6,
	      "uri": "http://tools.ietf.org/html/draft-ietf-avtext-framemarking-07"
	    },
	    {
	      "value": 11,
	      "uri": "urn:3gpp:video-orientation"
	    },
	    {
	      "value": 12,
	      "uri": "urn:ietf:params:rtp-hdrext:toffset"
	    }
	  ];

	  const videoTemplate = {
	    "rtp": [
	      {
	        "payload": 101,
	        "codec": "VP8",
	        "rate": 90000
	      },
	      {
	        "payload": 102,
	        "codec": "rtx",
	        "rate": 90000
	      }
	    ],
	    "fmtp": [
	      {
	        "payload": 102,
	        "config": "apt=101"
	      }
	    ],
	    "type": "video",
	    "port": 7,
	    "protocol": "UDP/TLS/RTP/SAVPF",
	    "payloads": "101 102",
	    "connection": {
	      "version": 4,
	      "ip": "127.0.0.1"
	    },
	    "rtcpFb": [
	      {
	        "payload": 101,
	        "type": "transport-cc",
	        "subtype": ""
	      },
	      {
	        "payload": 101,
	        "type": "ccm",
	        "subtype": "fir"
	      },
	      {
	        "payload": 101,
	        "type": "nack",
	        "subtype": ""
	      },
	      {
	        "payload": 101,
	        "type": "nack",
	        "subtype": "pli"
	      }
	    ],
	    "setup": "actpass",
	    "mid": 1,
	    "msid": "",
	    "direction": "",
	    "iceUfrag": "",
	    "icePwd": "",
	    "candidates": [],
	    "endOfCandidates": "end-of-candidates",
	    "iceOptions": "renomination",
	    "ssrcs": [],
	    "ssrcGroups": [],
	    "rtcpMux": "rtcp-mux",
	    "rtcpRsize": "rtcp-rsize"
	  };

	  const remoteSdpObj = Object.assign({}, sdpTemplate);

	  remoteSdpObj.fingerprint = {
	    "type": remoteDTLSParameters.fingerprint.algorithm,
	    "hash": remoteDTLSParameters.fingerprint.value
	  };

	  let medias = [];
	  let mids = [];
	  for (let [key, receiver] of receivers) {
	    // console.log(receiver);
	    let media;
	    if (receiver.kind === 'audio') {

	      media = Object.assign({}, audioTemplate);
	      if (receiver.active) {
	        media.direction = 'sendonly';
	        media.ext = audioExt;
	      } else {
	        media.direction = 'inactive';
	      }

	    } else if (receiver.kind == 'video') {

	      media = Object.assign({}, videoTemplate);

	      if (receiver.active) {
	        media.direction = 'sendonly';
	        media.ext = videoExt;
	      } else {
	        media.direction = 'inactive';
	      }
	    }


	    media.mid = String(receiver.mid);
	    media.msid = `${receiver.rtpParameters.rtcp.cname} ${receiver.receiverId}`;
	    media.iceUfrag = remoteICEParameters.usernameFragment;
	    media.icePwd = remoteICEParameters.password;

	    media.candidates = remoteICECandidates;

	    media.ssrcs = [
	      {
	        "id": receiver.rtpParameters.encodings[0].ssrc,
	        "attribute": "cname",
	        "value": receiver.rtpParameters.rtcp.cname
	      }
	    ];

	    medias.push(media);

	    mids.push(receiver.mid);
	  }


	  remoteSdpObj.media = medias;

	  remoteSdpObj.groups = [
	    {
	      "type": "BUNDLE",
	      "mids": mids.join(" ")
	    }
	  ];

	  let remoteSdp = lib.write(remoteSdpObj);
	  return remoteSdp;
	}

	//TODO: get setup
	function getDtls(localSdpObj) {
	  // console.log(JSON.stringify(localSdpObj));
	  for (let media of localSdpObj.media) {
	    if (media.fingerprint) {
	      const dtlsParameters =
	      {
	        setup: 'active',
	        fingerprint: {
	          algorithm: media.fingerprint.type,
	          value: media.fingerprint.hash
	        }
	      };

	      return dtlsParameters
	    }
	  }
	}

	function getSenderData(sender) {
	  let producingData;
	  if (sender.kind === 'audio') {
	    const sendingRtpParameters = {
	      "codecs": [
	        {
	          "mimeType": "audio/opus",
	          "payloadType": 111,
	          "clockRate": 48000,
	          "channels": 2,
	          "parameters": {
	            "minptime": 10,
	            "useinbandfec": 1,
	            "sprop-stereo": 1,
	            "usedtx": 1
	          },
	          "rtcpFeedback": [
	            {
	              "type": "transport-cc",
	              "parameter": ""
	            }
	          ]
	        }
	      ],
	      "headerExtensions": [
	        {
	          "uri": "urn:ietf:params:rtp-hdrext:sdes:mid",
	          "id": 4,
	          "encrypt": false,
	          "parameters": {}
	        },
	        {
	          "uri": "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
	          "id": 2,
	          "encrypt": false,
	          "parameters": {}
	        },
	        {
	          "uri": "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
	          "id": 3,
	          "encrypt": false,
	          "parameters": {}
	        },
	        {
	          "uri": "urn:ietf:params:rtp-hdrext:ssrc-audio-level",
	          "id": 1,
	          "encrypt": false,
	          "parameters": {}
	        }
	      ],
	      "mid": sender.mid,
	      "rtcp":
	      {
	        "reducedSize": true
	      }
	    };

	    const ssrc = sender.ssrcs[0].id;
	    let cname = null;
	    for (let s of sender.ssrcs) {
	      if (s.attribute == 'cname') {
	        cname = s.value;
	        break;
	      }
	    }

	    sendingRtpParameters.rtcp.cname = cname;
	    sendingRtpParameters.encodings = [
	      {
	        "ssrc": ssrc,
	        "dtx": false
	      }
	    ];

	    // console.log(sendingRtpParameters);
	    producingData = {
	      "kind": "audio",
	      "rtpParameters": sendingRtpParameters,
	    };
	  } else if (sender.kind === 'video') {
	    const sendingRtpParameters = {
	      "codecs": [
	        {
	          "mimeType": "video/VP8",
	          "payloadType": 96,
	          "clockRate": 90000,
	          "channels": 1,
	          "parameters": {},
	          "rtcpFeedback": [
	            {
	              "type": "goog-remb",
	              "parameter": ""
	            },
	            {
	              "type": "transport-cc",
	              "parameter": ""
	            },
	            {
	              "type": "ccm",
	              "parameter": "fir"
	            },
	            {
	              "type": "nack",
	              "parameter": ""
	            },
	            {
	              "type": "nack",
	              "parameter": "pli"
	            }
	          ]
	        },
	        {
	          "mimeType": "video/rtx",
	          "payloadType": 97,
	          "clockRate": 90000,
	          "channels": 1,
	          "parameters": {
	            "apt": 96
	          },
	          "rtcpFeedback": []
	        }
	      ],
	      "headerExtensions": [
	        {
	          "uri": "urn:ietf:params:rtp-hdrext:sdes:mid",
	          "id": 4,
	          "encrypt": false,
	          "parameters": {}
	        },
	        {
	          "uri": "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
	          "id": 5,
	          "encrypt": false,
	          "parameters": {}
	        },
	        {
	          "uri": "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
	          "id": 6,
	          "encrypt": false,
	          "parameters": {}
	        },
	        {
	          "uri": "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
	          "id": 2,
	          "encrypt": false,
	          "parameters": {}
	        },
	        {
	          "uri": "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
	          "id": 3,
	          "encrypt": false,
	          "parameters": {}
	        },
	        {
	          "uri": "http://tools.ietf.org/html/draft-ietf-avtext-framemarking-07",
	          "id": 8,
	          "encrypt": false,
	          "parameters": {}
	        },
	        {
	          "uri": "urn:3gpp:video-orientation",
	          "id": 13,
	          "encrypt": false,
	          "parameters": {}
	        },
	        {
	          "uri": "urn:ietf:params:rtp-hdrext:toffset",
	          "id": 14,
	          "encrypt": false,
	          "parameters": {}
	        }
	      ],

	      "rtcp": {
	        "reducedSize": true
	      },
	      "mid": sender.mid
	    };

	    let encodings;

	    if (sender.ssrcGroups != undefined) {

	      encodings = [
	        {
	          "ssrc": sender.ssrcs[0].id,
	          "rtx": {
	            "ssrc": sender.ssrcs[4].id
	          },
	          "dtx": false
	        }
	      ];
	    } else {
	      encodings = [
	        {
	          "ssrc": sender.ssrcs[0].id,
	          "dtx": false
	        }
	      ];
	    }

	    let cname = null;
	    for (let s of sender.ssrcs) {
	      if (s.attribute == 'cname') {
	        cname = s.value;
	        break;
	      }
	    }

	    sendingRtpParameters.rtcp.cname = cname;
	    sendingRtpParameters.encodings = encodings;

	    // console.log(sendingRtpParameters);
	    producingData = {
	      "kind": "video",
	      "rtpParameters": sendingRtpParameters,
	    };
	  }
	  return producingData;
	}

	class Packet {
	  constructor(y, n) {
	    this.resolve = data => {
	      y(data);
	    };
	    this.reject = error => {
	      n(error);
	    };
	  }
	}

	//TODO: add timeout
	class Socket {
	  constructor(url, params) {
	    this.url = url;
	    this.params = params;
	    this.messages = new Map();

	    this.onnotification = null;
	    this.onclose = null;
	  }

	  getFullURL() {
	    let urlObj = new URL(this.url);
	    let encoded = btoa(JSON.stringify(this.params));
	    urlObj.searchParams.set('params', encoded);
	    return urlObj.toString();
	  }

	  init() {
	    this.ws = new WebSocket(this.getFullURL());

	    this.ws.onmessage = event => {
	      let data = JSON.parse(event.data);
	      console.log(data);

	      let { id, method, params } = data;

	      if (method === 'response') {
	        let packet = this.messages.get(id);
	        if (packet) {
	          packet.resolve(params);
	        }
	      } else if (method === 'notification') {
	        let { event, data } = params;
	        this.onnotification(event, data);
	      }
	    };

	    this.ws.onclose = _ => {
	      this.onclose();
	    };

	    //TODO: error
	    const executor = (y, n) => {
	      this.ws.onopen = event => {
	        y();
	      };
	    };

	    return new Promise(executor);
	  }

	  async request(params) {
	    const id = randomInitId(8);

	    this.sendJSON({
	      'method': 'request',
	      id,
	      params,
	    });

	    const executor = (y, n) => {
	      const packet = new Packet(y, n);

	      this.messages.set(id, packet);
	    };

	    return new Promise(executor);
	  }

	  sendJSON(json) {
	    try {
	      let jsonString = JSON.stringify(json);
	      this.ws.send(jsonString);
	    } catch (e) {
	      // TODO:
	    }
	  }
	}

	class AsyncQueue {
	  constructor() {
	    this.running = false;
	    this.queue = new Array();
	  }

	  push(execObj, task, parameter) {
	    if (this.running) {
	      this.queue.push([execObj, task, parameter]);
	    } else {
	      this.running = true;
	      this.executeTask(execObj, task, parameter);
	    }
	  }

	  executeTask(execObj, task, parameter) {
	    task.call(execObj, parameter).then(() => {
	      if (this.queue.length > 0) {
	        let [nextExecObj, nextTask, nextParameter] = this.queue.shift();
	        this.executeTask(nextExecObj, nextTask, nextParameter);
	      } else {
	        this.running = false;
	      }
	    });
	  }

	}

	class Sender {
	  constructor(track, transceiver) {
	    this.track = track;
	    this.transceiver = transceiver;

	    this.senderId = 0;
	  }

	  get id() {
	    return this.track.id;
	  }

	  get kind() {
	    return this.track.kind;
	  }

	  // defined after setLocalDescription
	  get mid() {
	    return this.transceiver.mid;
	  }

	  get available() {
	    return !(this.transceiver.direction === 'inactive');
	  }

	  get isStopped() {
	    return this.transceiver.stopped;
	  }

	}

	class Transport {
	  constructor(id, remoteICECandidates, remoteICEParameters, remoteDTLSParameters) {
	    this.id = id;
	    this.remoteICECandidates = remoteICECandidates;
	    this.remoteICEParameters = remoteICEParameters;
	    this.remoteDTLSParameters = remoteDTLSParameters;

	    this.pc = null;

	  }
	  
	} 

	Transport.TRANSPORT_NEW = 0;
	Transport.TRANSPORT_CONNECTING = 1;
	Transport.TRANSPORT_CONNECTED = 2;

	class Publisher extends Transport {
	  constructor(id, remoteICECandidates, remoteICEParameters, remoteDTLSParameters) {
	    super(id, remoteICECandidates, remoteICEParameters, remoteDTLSParameters);

	    this.senders = [];

	    this.asyncQueue = new AsyncQueue();
	    // new 0 , initing 1 , inited 2 , ready 3
	    this.state = 0;

	    this.isGotDtls = false;

	    this.localDTLSParameters = null;
	  }

	  init() {
	    //配置重要
	    this.pc = new RTCPeerConnection({ iceServers: [], iceTransportPolicy: 'all', bundlePolicy: 'max-bundle', rtcpMuxPolicy: 'require', sdpSemantics: "unified-plan" });

	    this.pc.onconnectionstatechange = event => {
	      switch (this.pc.connectionState) {
	        case "connected":
	          this.state = 3;
	          break;
	      }
	    };
	  }

	  getLocalSdpData(sender, localSdp) {
	    let localSdpObj = lib.parse(localSdp.sdp);

	    for (let m of localSdpObj.media) {
	      if (m.mid == sender.mid) {
	        sender.ssrcs = m.ssrcs;
	        sender.ssrcGroups = m.ssrcGroups;
	      }
	    }

	    if (false === this.isGotDtls) {
	      this.isGotDtls = true;

	      this.localDTLSParameters = getDtls(localSdpObj);

	      this.ondtls(this.localDTLSParameters);

	    }
	  }

	  send(track) {
	    this.asyncQueue.push(this, this._send, track);
	  }

	  async _send(track) {
	    const transceiver = await this.pc.addTransceiver(track, {
	      direction: 'sendonly',
	      //TODO: streams: [t.stream]
	    });
	    const sender = new Sender(track, transceiver);
	    this.senders.push(sender);

	    const localSdp = await this.pc.createOffer();
	    await this.pc.setLocalDescription(localSdp);//mid after setLocalSdp

	    this.getLocalSdpData(sender, localSdp);

	    let remoteSdp = pubRemoteSdpGen(this.senders, this.remoteICECandidates, this.remoteICEParameters, this.remoteDTLSParameters);

	    await this.pc.setRemoteDescription(remoteSdp);


	    const producingData = getSenderData(sender);
	    if (producingData) {
	      producingData.metadata = {
	        test: 'test'
	      };
	      this.onsender(producingData, sender);
	    }

	  }

	  stopSender(senderId) {
	    this.asyncQueue.push(this, this._stopSender, senderId);
	  }
	  async _stopSender(senderId) {
	    //TODO: check sender 
	    for (let sender of this.senders) {
	      if (sender.senderId === senderId) {
	        this.pc.removeTrack(sender.transceiver.sender);

	        let localSdp = await this.pc.createOffer();

	        let localSdpObj = lib.parse(localSdp.sdp);
	        await this.pc.setLocalDescription(localSdp);
	        let remoteSdp = pubRemoteSdpGen(this.senders, this.remoteICECandidates, this.remoteICEParameters, this.remoteDTLSParameters);
	        await this.pc.setRemoteDescription(remoteSdp);

	        this.onsenderclosed(sender.senderId);
	      }
	    }
	  }
	}

	class Receiver {
	  constructor(senderId, tokenId, receiverId, kind, rtpParameters, metadata) {
	    this.senderId = senderId;
	    this.tokenId = tokenId;
	    this.receiverId = receiverId;
	    this.rtpParameters = rtpParameters;

	    this.kind = kind;

	    this.metadata = metadata;

	    this.active = false;
	  }
	}

	class Subscriber extends Transport {
	  constructor(id, remoteICECandidates, remoteICEParameters, remoteDTLSParameters) {
	    super(id, remoteICECandidates, remoteICEParameters, remoteDTLSParameters);

	    this.receivers = new Map();

	    this.asyncQueue = new AsyncQueue();

	    this.state = Transport.TRANSPORT_NEW;

	    this.isGotDtls = false;

	    this.currentMid = 0;

	  }

	  removeReceiverByTokenId(tokenId) {
	    for (let [_, receiver] of this.receivers) {
	      if (tokenId === receiver.tokenId) {
	        this.removeReceiver(receiver.senderId);
	      }
	    }
	  }

	  addReceiver(senderId, tokenId, receiverId, kind, rtpParameters, metadata) {
	    const receiver = new Receiver(senderId, tokenId, receiverId, kind, rtpParameters, metadata);
	    receiver.mid = String(this.currentMid++);
	    this.receivers.set(senderId, receiver);
	    return receiver;
	  }

	  receive(senderId) {
	    const receiver = this.receivers.get(senderId);
	    if (receiver) {
	      this.asyncQueue.push(this, this._receive, receiver);
	    }
	  }

	  async _receive(receiver) {
	    if (!receiver.active) {
	      receiver.active = true;
	    }

	    let remoteSdp = subRemoteSdpGen(this.receivers, this.remoteICECandidates,
	      this.remoteICEParameters, this.remoteDTLSParameters);

	    await this.pc.setRemoteDescription(new RTCSessionDescription({
	      type: 'offer',
	      sdp: remoteSdp
	    }));
	    let answer = await this.pc.createAnswer();
	    await this.pc.setLocalDescription(answer);

	    //track
	    const transceiver = await this.pc.getTransceivers().find(t => t.mid === receiver.mid);
	    receiver.transceiver = transceiver;
	    this.ontrack(transceiver.receiver.track, receiver);

	    //TODO: consumer resume

	    if (!this.isGotDtls) {
	      this.isGotDtls = true;
	      //dtls
	      let answerSdpObj = lib.parse(answer.sdp);
	      let dtls = getDtls(answerSdpObj);

	      this.ondtls(dtls);
	    }

	  }

	  removeReceiver(senderId) {
	    const receiver = this.receivers.get(senderId);
	    if (receiver && receiver.active) {
	      this.asyncQueue.push(this, this._removeReceiver, receiver);
	    }
	  }

	  async _removeReceiver(receiver) {
	    receiver.active = false;

	    let remoteSdp = subRemoteSdpGen(this.receivers, this.remoteICECandidates,
	      this.remoteICEParameters, this.remoteDTLSParameters);

	    await this.pc.setRemoteDescription(new RTCSessionDescription({
	      type: 'offer',
	      sdp: remoteSdp
	    }));
	    let answer = await this.pc.createAnswer();
	    await this.pc.setLocalDescription(answer);

	    this.onremovereceiver(receiver);
	  }

	  init() {
	    this.pc = new RTCPeerConnection();
	  }
	}

	class Session {
	  constructor(url, sessionId, tokenId, options = { metadata: {} }) {
	    this.url = url;
	    this.sessionId = sessionId;
	    this.tokenId = tokenId;

	    const { metadata } = options;
	    this.metadata = metadata;

	    this.socket = null;

	    this.publisher = null;
	    this.subscriber = null;

	    //event
	    this.onin = null;
	    this.onout = null;
	    this.onsender = null;
	    this.onclose = null;
	  }

	  async init(options = { pub: true, sub: true }) {
	    //TODO: set default value
	    const { pub, sub } = options;

	    this.socket = new Socket(this.url, {
	      'sessionId': this.sessionId,
	      'tokenId': this.tokenId,
	      'metadata': this.metadata,
	    });

	    this.socket.onclose = _ => {
	      this.onclose();
	    };

	    this.socket.onnotification = (event, data) => {
	      this.handleNotification(event, data);
	    };

	    await this.socket.init();

	    const transportParameters = await this.socket.request({
	      event: 'join',
	      data: {
	        pub,
	        sub,
	      }
	    });
	    if (pub) {
	      this.initTransport('pub', transportParameters.pub);
	    }
	    if (sub) {
	      this.initTransport('sub', transportParameters.sub);
	    }
	  }

	  initTransport(role, transportParameters) {
	    const { id, iceCandidates, iceParameters, dtlsParameters } = transportParameters;

	    if (role === 'pub') {
	      this.publisher = new Publisher(id, iceCandidates, iceParameters, dtlsParameters);

	      //TODO: mv to init
	      this.publisher.onsenderclosed = async senderId => {
	        await this.socket.request({
	          event: 'unpublish',
	          data: {
	            transportId: this.publisher.id,
	            senderId
	          }
	        });
	      };

	      this.publisher.ondtls = async dtlsParameters => {
	        await this.socket.request({
	          event: 'dtls',
	          data: {
	            transportId: this.publisher.id,
	            role: 'pub',
	            dtlsParameters
	          }
	        });
	      };

	      this.publisher.onsender = async (producingParameters, sender) => {
	        const data = await this.socket.request({
	          event: 'publish',
	          data: {
	            transportId: this.publisher.id,
	            ...producingParameters
	          }
	        });
	        const { senderId } = data;
	        sender.senderId = senderId;
	        this.onsender(sender);

	      };

	      //init pub
	      this.publisher.init();

	      this.publisher.state = 2;

	    } else {
	      this.subscriber = new Subscriber(id, iceCandidates, iceParameters, dtlsParameters);

	      this.subscriber.ondtls = async dtlsParameters => {
	        await this.socket.request({
	          event: 'dtls',
	          data: {
	            transportId: this.subscriber.id,
	            role: 'sub',
	            dtlsParameters
	          }
	        });
	      };

	      this.subscriber.ontrack = (track, receiver) => {
	        this.ontrack(track, receiver);
	      };

	      this.subscriber.onremovereceiver = receiver => {
	        this.onunreceiver(receiver);
	        this.socket.request({
	          event: 'unsubscribe',
	          data: {
	            transportId: this.subscriber.id,
	            senderId: receiver.senderId,
	          }
	        });
	      };

	      this.subscriber.init();

	      //TODO: state change

	    }

	  }

	  //TODO: add codec , simulcast config
	  async publish(track, options = {
	    codec: 'vp8', svc: false
	  }) {
	    if (this.publisher.state >= 2) {
	      console.log('pub send');
	      this.publisher.send(track);
	    }
	  }

	  async unpublish(senderId) {
	    this.publisher.stopSender(senderId);
	  }

	  async subscribe(senderId) {
	    this.subscriber.receive(senderId);
	  }

	  async unsubscribe(senderId) {
	    this.subscriber.removeReceiver(senderId);
	  }

	  async pause(senderId) {
	    let transportId = null;
	    if(this.subscriber.receivers.get(senderId)){
	      transportId = this.subscriber.transportId;
	    }
	  }

	  async resume() {

	  }



	  handleNotification(event, data) {
	    console.log('notification: ', event, data);
	    switch (event) {
	      case 'join': {
	        let { tokenId, metadata } = data;
	        this.onin(tokenId, metadata);
	        break;
	      }      case 'leave': {
	        let { tokenId } = data;
	        //TODO: release all receiver
	        if (this.subscriber) {
	          this.subscriber.removeReceiverByTokenId(tokenId);
	        }
	        this.onout(tokenId);
	        break;
	      }      case 'publish': {
	        let { senderId, tokenId, metadata, kind, rtpParameters, receiverId } = data;
	        let receiver = this.subscriber.addReceiver(senderId, tokenId, receiverId, kind, rtpParameters, metadata);
	        this.onreceiver(receiver, tokenId, senderId, metadata);
	        break;
	      }      case 'unpublish': {
	        let { senderId, tokenId } = data;
	        this.subscriber.removeReceiver(senderId);

	        break;
	      }
	      default: {
	        console.log('unknown event ', event);
	      }
	    }
	  }

	}

	var index = { Session };

	return index;

})));
