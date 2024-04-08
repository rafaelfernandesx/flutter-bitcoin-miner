import 'dart:convert';
import 'dart:developer';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:hex/hex.dart';
import 'package:http/http.dart' as http;

class BitcoinMiner {
  final BitcoinRpcClient bitcoinRpcClient;

  BitcoinMiner(this.bitcoinRpcClient);

  Map<String, String>? getBlockHeaderHex(
      BlockTemplate blockTemplate, List<int> coinbaseMessage, String address) {
    String coinbaseHex = bytesToHex(coinbaseMessage);
    Map<String, dynamic> coinbaseTx = {};
    blockTemplate.transactions.insert(0, coinbaseTx);
    blockTemplate.nonce = 0;
    // String targetHash = blockBits2Target(blockTemplate.bits);
    int nonce = 0;
    coinbaseTx = createCoinbaseTransaction(coinbaseHex, address, nonce,
        blockTemplate.coinbasevalue, blockTemplate.height);
    blockTemplate.transactions[0] = coinbaseTx;
    String merkleRoot = calculateMerkleRoot(blockTemplate.transactions);
    blockTemplate.merkleroot = merkleRoot;
    List<int> blockHeader = blockMakeHeader(blockTemplate);
    String headerHex = bytesToHex(blockHeader);

    return {
      'headerHex': headerHex,
      'targetHex': blockTemplate.target,
    };
  }

  String blockComputeRawHash(String headerHex) {
    final hash = String.fromCharCodes(
      sha256
          .convert(sha256.convert(hexToBytes(headerHex)).bytes)
          .bytes
          .reversed,
    );
    final hash2 = strToHex(hash);
    return hash2;
  }

  void writeFile(String fileName, String content) {
    File file = File(fileName);
    file.writeAsStringSync(content);
  }

  List<int> pack(String format, dynamic value) {
    if (format == 'V') {
      return Uint32List.fromList([value]).buffer.asUint8List();
    }
    throw FormatException('Unsupported format: $format');
  }

  String int2lehex(int value, int width) {
    // Convert an unsigned integer to a little endian ASCII hex string.
    List<int> bytes = [];
    for (int i = 0; i < width; i++) {
      bytes.add(value & 0xFF);
      value >>= 8;
    }
    bytes = bytes.reversed.toList();
    String hex = bytes
        .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
        .toList()
        .reversed
        .join();
    return hex;
  }

  String bitcoinaddress2hash160(String address) {
    String decoded = HEX.encode(base58Decode(address).codeUnits);
    String hash160 = decoded.substring(0, 40);
    return hash160;
  }

  String base58Decode(String base58) {
    String alphabet =
        '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    BigInt base = BigInt.zero;
    for (int i = 0; i < base58.length; i++) {
      base = base * BigInt.from(58);
      base += BigInt.from(alphabet.indexOf(base58[i]));
    }
    String base256 = '';
    while (base > BigInt.zero) {
      BigInt remainder = base % BigInt.from(256);
      base = base ~/ BigInt.from(256);
      base256 = String.fromCharCode(remainder.toInt()) + base256;
    }
    return base256;
  }

  Uint8List blockMakeHeader(BlockTemplate blockTemplate) {
    String header = "";
    header += listToString(pack("V", blockTemplate.version));
    String previousBlockHash =
        listToString(hexToBytes(blockTemplate.previousblockhash));
    header += previousBlockHash.split('').reversed.join();
    String merkleRootHash = listToString(hexToBytes(blockTemplate.merkleroot!));
    header += merkleRootHash.split('').reversed.join();
    header += listToString(pack("V", blockTemplate.curtime));
    String targetBits = listToString(hexToBytes(blockTemplate.bits));
    header += targetBits.split('').reversed.join();
    header += listToString(pack("V", blockTemplate.nonce));
    return Uint8List.fromList(header.codeUnits);
  }

  String txEncodeCoinbaseHeight(int height) {
    int heightLength = math.log(height) ~/ math.log(2) + 1;
    int width = ((heightLength + 7) / 8).floor();

    List<int> widthBytes = [width];
    String widthHex =
        widthBytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

    String heightHex = int2lehex(height, width);

    String res = widthHex + heightHex;
    return res;
  }

  String listToString(List<int> list) {
    final charCodes = list.map((e) => String.fromCharCode(e)).toList();
    return charCodes.join('');
  }

  String txMakeCoinbase(
      String coinbaseScript, String address, int value, int height) {
    String coinbaseScriptEncoded =
        txEncodeCoinbaseHeight(height) + coinbaseScript;

    String pubkeyScript = "76a914${bitcoinaddress2hash160(address)}88ac";

    String tx = "";
    tx += "01000000";
    tx += "01";
    tx += "0" * 64;
    tx += "ffffffff";
    tx += int2varinthex(coinbaseScriptEncoded.length ~/ 2);
    tx += coinbaseScriptEncoded;
    tx += "ffffffff";
    tx += "01";
    tx += int2lehex(value, 8);
    int pubkeyScriptLength = pubkeyScript.length ~/ 2;
    tx += int2varinthex(pubkeyScriptLength);
    tx += pubkeyScript;
    tx += "00000000";

    return tx;
  }

  Map<String, dynamic> createCoinbaseTransaction(String message, String address,
      int nonce, int coinbaseValue, int height) {
    String coinbaseScript = buildCoinbaseScript(message, nonce);
    String txData =
        txMakeCoinbase(coinbaseScript, address, coinbaseValue, height);

    Map<String, dynamic> coinbaseTx = {
      'data': txData,
      'hash': '',
      'vin': [
        {
          'coinbase': coinbaseScript,
          'sequence': 0xffffffff,
        },
      ],
      'vout': [],
    };

    coinbaseTx['hash'] = calculateTransactionHash(txData);

    return coinbaseTx;
  }

  String calculateTransactionHash(String tx) {
    String hash = '';
    List<int> txBytes = hexToBytes(tx);
    List<int> hash1 = sha256.convert(sha256.convert(txBytes).bytes).bytes;
    hash = bytesToHex(hash1.reversed.toList());
    return hash;
  }

  String calculateMerkleRoot(List<dynamic> txHashes) {
    // Convert list of ASCII hex transaction hashes into bytes
    List<String> ntxHashes = [];
    for (var txHash in txHashes) {
      ntxHashes.add(
        String.fromCharCodes(hexToBytes(txHash['hash']!).reversed.toList()),
      );
    }

    List<String> txHashesList = ntxHashes;

    // Iteratively compute the merkle root hash
    while (txHashesList.length > 1) {
      // Duplicate last hash if the list is odd
      if (txHashesList.length % 2 != 0) {
        txHashesList.add(txHashesList.last);
      }

      List<String> txHashesNew = [];
      int count = (txHashesList.length / 2).floor();
      for (int i = 0; i < count; i++) {
        // Concatenate the next two
        String concat = txHashesList.removeAt(0) + txHashesList.removeAt(0);
        // Hash them
        String concatHash = String.fromCharCodes(
          sha256.convert(sha256.convert(concat.codeUnits).bytes).bytes,
        );
        // Add them to our working list
        txHashesNew.add(concatHash);
      }
      txHashesList = txHashesNew;
    }

    // Format the root in big endian ascii hex
    String txHash = HEX.encode(txHashesList[0].codeUnits.reversed.toList());
    return txHash;
  }

  String blockBits2Target(String bits) {
    List<int> bitsBytes = hexToBytes(bits);
    int shift = bitsBytes[0] - 3;
    List<int> value = bitsBytes.sublist(1);
    List<int> target = [...value, ...List<int>.filled(shift, 0)];
    target = List<int>.filled(32 - target.length, 0) + target;
    return bytesToHex(target);
  }

  String buildBlock(BlockTemplate blockTemplate) {
    String submission = '';
    submission += bytesToHex(blockMakeHeader(blockTemplate));
    submission += int2varinthex(blockTemplate.transactions.length);
    for (var tx in blockTemplate.transactions) {
      submission += tx['data'];
    }
    return submission;
  }

  List<int> hexToBytes(String hex) {
    List<int> bytes = [];
    for (int i = 0; i < hex.length; i += 2) {
      String hexByte = hex.substring(i, i + 2);
      bytes.add(int.parse(hexByte, radix: 16));
    }
    return bytes;
  }

  String bytesToHex(List<int> bytes) {
    String hex = '';
    for (int byte in bytes) {
      hex += byte.toRadixString(16).padLeft(2, '0');
    }
    return hex;
  }

  String strToHex(String str) {
    String hex = HEX.encode(str.codeUnits);
    return hex;
  }

  String listToHex(List<int> list) {
    final str = String.fromCharCodes(list);
    String hex = utf8.encode(str).map((e) => e.toRadixString(16)).join();
    return hex;
  }

  String buildCoinbaseScript(String message, int nonce) {
    String result = message + int2lehex(nonce, 4);
    return result;
  }

  String int2varinthex(int value) {
    if (value < 0xfd) {
      return int2lehex(value, 1);
    } else if (value <= 0xffff) {
      return "fd${int2lehex(value, 2)}";
    } else if (value <= 0xffffffff) {
      return "fe${int2lehex(value, 4)}";
    } else {
      return "ff${int2lehex(value, 8)}";
    }
  }
}

class BitcoinRpcClient {
  final String rpcUrl;
  final String rpcUser;
  final String rpcPass;

  BitcoinRpcClient(this.rpcUrl, this.rpcUser, this.rpcPass);

  Future<Map<String, dynamic>> _rpc(String method, [dynamic params]) async {
    final rpcId = math.Random().nextInt(2147483647);
    final data = jsonEncode({
      'id': rpcId,
      'method': method,
      'params': params,
    });

    final auth = base64Encode(utf8.encode('$rpcUser:$rpcPass'));
    final headers = {'Authorization': 'Basic $auth'};
    try {
      final response = await http.post(
        // Uri.parse(rpcUrl),
        Uri.parse('https://go.getblock.io/6edfe3170d224f748ae86b14e4df45da'),
        headers: headers,
        body: data,
        encoding: utf8,
      );
      final jsonResponse = jsonDecode(response.body);

      if (jsonResponse['id'] != rpcId) {
        throw Exception(
            'Invalid response id: got ${jsonResponse['id']}, expected $rpcId');
      } else if (jsonResponse['error'] != null) {
        throw Exception('RPC error: ${jsonResponse['error']}');
      }

      return jsonResponse;
    } catch (e) {
      inspect(e);
      rethrow;
    }
  }

  Future<BlockTemplate?> getBlockTemplate() async {
    try {
      final result = await _rpc('getblocktemplate', [
        {
          "rules": ["segwit"]
        }
      ]);
      final blockTemplate = BlockTemplate.fromJson(result['result']);
      return blockTemplate;
    } catch (e) {
      return null;
    }
  }

  Future<dynamic> submitBlock(String blockSubmission) {
    return _rpc('submitblock', [blockSubmission]);
  }
}

class BlockTemplate {
  final List<String> capabilities;
  final int version;
  final List<String> rules;
  final dynamic vbavailable;
  final int vbrequired;
  final String previousblockhash;
  final List<dynamic> transactions;
  final dynamic coinbaseaux;
  final int coinbasevalue;
  final String longpollid;
  final String target;
  final int mintime;
  final List<String> mutable;
  final String noncerange;
  final int sigoplimit;
  final int sizelimit;
  final int weightlimit;
  final int curtime;
  final String bits;
  final int height;
  final String defaultWitnessCommitment;
  //added after getting the block template
  int? nonce;
  String? merkleroot;
  String? blockHash;

  BlockTemplate({
    required this.capabilities,
    required this.version,
    required this.rules,
    required this.vbavailable,
    required this.vbrequired,
    required this.previousblockhash,
    required this.transactions,
    required this.coinbaseaux,
    required this.coinbasevalue,
    required this.longpollid,
    required this.target,
    required this.mintime,
    required this.mutable,
    required this.noncerange,
    required this.sigoplimit,
    required this.sizelimit,
    required this.weightlimit,
    required this.curtime,
    required this.bits,
    required this.height,
    required this.defaultWitnessCommitment,
    this.nonce = 0,
    this.merkleroot,
    this.blockHash,
  });

  factory BlockTemplate.fromJson(Map<String, dynamic> json) {
    return BlockTemplate(
      capabilities: List<String>.from(json['capabilities']),
      version: json['version'],
      rules: List<String>.from(json['rules']),
      vbavailable: json['vbavailable'],
      vbrequired: json['vbrequired'],
      previousblockhash: json['previousblockhash'],
      transactions: json['transactions'],
      coinbaseaux: json['coinbaseaux'],
      coinbasevalue: json['coinbasevalue'],
      longpollid: json['longpollid'],
      target: json['target'],
      mintime: json['mintime'],
      mutable: List<String>.from(json['mutable']),
      noncerange: json['noncerange'],
      sigoplimit: json['sigoplimit'],
      sizelimit: json['sizelimit'],
      weightlimit: json['weightlimit'],
      curtime: json['curtime'],
      bits: json['bits'],
      height: json['height'],
      defaultWitnessCommitment: json['default_witness_commitment'],
      nonce: json['nonce'] ?? 0,
      merkleroot: json['merkleroot'],
      blockHash: json['hash'],
    );
  }
}

class Transaction {
  final String data;
  final String txid;
  final String hash;
  final List<int> depends;
  final int fee;
  final int sigops;
  final int weight;

  Transaction({
    required this.data,
    required this.txid,
    required this.hash,
    required this.depends,
    required this.fee,
    required this.sigops,
    required this.weight,
  });

  factory Transaction.fromJson(Map<String, dynamic> json) {
    return Transaction(
      data: json['data'],
      txid: json['txid'],
      hash: json['hash'],
      depends: List<int>.from(json['depends']),
      fee: json['fee'],
      sigops: json['sigops'],
      weight: json['weight'],
    );
  }
}
