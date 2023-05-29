import 'dart:convert';
import 'dart:developer';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;

class BitcoinMiner {
  final BitcoinBlockTemplate rpcBlockTemplate;
  final BitcoinBlockSubmission rpcBlockSubmission;

  BitcoinMiner(this.rpcBlockTemplate, this.rpcBlockSubmission);

  Future<Map<String, dynamic>>? mineBlock(List<int> coinbaseMessage, String address, int extranonceStart, {int? timeout, num debugnonceStart = 0}) async {
    String coinbaseHex = bytesToHex(coinbaseMessage);
    Map<String, dynamic> blockTemplate = await rpcBlockTemplate.getBlockTemplate();
    Map<String, dynamic> coinbaseTx = {};
    blockTemplate['transactions'].insert(0, coinbaseTx);
    blockTemplate['nonce'] = 0;
    String targetHash = blockBits2Target(blockTemplate['bits']);
    int timeStart = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    int hashRateCount = 0;
    int nonce = extranonceStart;
    coinbaseTx = createCoinbaseTransaction(coinbaseHex, address, nonce, blockTemplate['coinbasevalue'], blockTemplate['height']);
    blockTemplate['transactions'][0] = coinbaseTx;
    String merkleRoot = calculateMerkleRoot(blockTemplate['transactions']);
    blockTemplate['merkleroot'] = merkleRoot;
    List<int> blockHeader = blockMakeHeader(blockTemplate);
    while (true) {
      blockHeader = blockHeader.sublist(0, 76);
      blockHeader = <int>[...blockHeader, ...pack('V', nonce)];
      List<int> blockHash = blockComputeRawHash(Uint8List.fromList(blockHeader));
      hashRateCount++;
      BigInt currentHash = hashToGmp(blockHash);
      BigInt targetHashGmp = hashToGmp(hexToBytes(targetHash));
      if (currentHash <= targetHashGmp) {
        // Save block template and info to files
        writeFile('minedblock${blockTemplate['height']}.json', jsonEncode(blockTemplate));
        blockTemplate['nonce'] = nonce;
        blockTemplate['hash'] = bytesToHex(blockHash);
        String blockSub = buildBlock(blockTemplate);
        dynamic result = await rpcBlockSubmission.submitBlock(blockSub);
        return result;
      }
      nonce++;
      if (debugnonceStart > 0 && nonce >= extranonceStart + debugnonceStart) {
        break;
      }
      if (timeout != null && (DateTime.now().millisecondsSinceEpoch ~/ 1000 - timeStart) >= timeout) {
        // print('Total hash: $hashRateCount in $timeout seconds');
        break;
      }
    }

    return {
      'hashRateCount': hashRateCount,
      'nonce': nonce,
      'height': blockTemplate['height'],
    };
  }

  void writeFile(String fileName, String content) {
    File file = File(fileName);
    file.writeAsStringSync(content);
  }

  BigInt hashToGmp(List<int> hash) {
    String hashHex = bytesToHex(hash);
    return BigInt.parse(hashHex, radix: 16);
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
    String hex = bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).toList().reversed.join();
    return hex;
  }

  String bitcoinaddress2hash160(String address) {
    String decoded = base58Decode(address);
    String hash160 = decoded.substring(1, 21);
    return hash160.codeUnits.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
  }

  String base58Decode(String base58) {
    String alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
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

  Uint8List blockMakeHeader(Map<String, dynamic> block) {
    String header = "";
    header += listToString(pack("V", block['version']));
    String previousBlockHash = listToString(hexToBytes(block['previousblockhash']));
    header += previousBlockHash.split('').reversed.join();
    String merkleRootHash = listToString(hexToBytes(block['merkleroot']));
    header += merkleRootHash.split('').reversed.join();
    header += listToString(pack("V", block['curtime']));
    String targetBits = listToString(hexToBytes(block['bits']));
    header += targetBits.split('').reversed.join();
    header += listToString(pack("V", block['nonce']));
    return Uint8List.fromList(header.codeUnits);
  }

  Uint8List blockComputeRawHash(Uint8List header) {
    List<int> hash1 = sha256.convert(header).bytes;
    Uint8List hash2 = Uint8List.fromList(sha256.convert(hash1).bytes.reversed.toList());
    return hash2;
  }

  String intToHex(int value, int width) {
    List<int> bytes = [width];
    String hex = bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
    return hex;
  }

  String txEncodeCoinbaseHeight(int height) {
    int heightLength = math.log(height) ~/ math.log(2) + 1;
    int width = ((heightLength + 7) / 8).floor();

    List<int> widthBytes = [width];
    String widthHex = widthBytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

    String heightHex = int2lehex(height, width);

    String res = widthHex + heightHex;
    return res;
  }

  String listToString(List<int> list) {
    final charCodes = list.map((e) => String.fromCharCode(e)).toList();
    return charCodes.join('');
  }

  String txMakeCoinbase(String coinbaseScript, String address, int value, int height) {
    String coinbaseScriptEncoded = txEncodeCoinbaseHeight(height) + coinbaseScript;

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

  Map<String, dynamic> createCoinbaseTransaction(String message, String address, int nonce, int coinbaseValue, int height) {
    String coinbaseScript = buildCoinbaseScript(message, nonce);
    String txData = txMakeCoinbase(coinbaseScript, address, coinbaseValue, height);

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

  String calculateMerkleRoot(List<dynamic> transactions) {
    if (transactions.length == 1) {
      return transactions[0]['hash'];
    }
    List<String> merkle = [];
    for (var transaction in transactions) {
      merkle.add(transaction['hash']);
    }
    while (merkle.length > 1) {
      List<String> level = [];
      for (int i = 0; i < merkle.length; i += 2) {
        String a = merkle[i];
        String b = (i + 1 < merkle.length) ? merkle[i + 1] : merkle[i];
        List<int> hash = sha256.convert(hexToBytes(a + b)).bytes;
        level.add(bytesToHex(sha256.convert(hash).bytes).split('').reversed.join());
      }
      merkle = level;
    }
    return merkle[0];
  }

  String blockBits2Target(String bits) {
    List<int> bitsBytes = hexToBytes(bits);
    int shift = bitsBytes[0] - 3;
    List<int> value = bitsBytes.sublist(1);
    List<int> target = [...value, ...List<int>.filled(shift, 0)];
    target = List<int>.filled(32 - target.length, 0) + target;
    return bytesToHex(target);
  }

  String buildBlock(Map<String, dynamic> block) {
    String submission = '';
    submission += bytesToHex(blockMakeHeader(block));
    submission += int2varinthex(block['transactions'].length);
    for (var tx in block['transactions']) {
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

  String buildCoinbaseScript(String message, int nonce) {
    String result = message + int2lehex(nonce, 4);
    return result;
  }

  String bin2hex(String input) {
    List<int> bytes = [];
    for (int i = 0; i < input.length; i += 2) {
      String hex = input.substring(i, i + 2);
      bytes.add(int.parse(hex, radix: 16));
    }
    String hexString = bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
    return hexString;
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

  int bitLength(int value) {
    String bin = BigInt.from(value).toRadixString(2);
    return bin.length;
  }

  int reverseBytesInWord(int word) {
    return (((word << 24) & 0xFF000000) | ((word << 8) & 0x00FF0000) | ((word >> 8) & 0x0000FF00) | ((word >> 24) & 0x000000FF));
  }

  Uint32List hexToReversedList(String hex, [bool reverseWords = true]) {
    Uint32List arr = Uint32List(hex.length ~/ 8);
    int word = 0;
    int index = 0;
    for (var i = hex.length; i > 0; i -= 8) {
      String test = hex.substring((i - 8), i);
      word = int.parse(hex.substring((i - 8), i), radix: 16);
      arr[index++] = reverseWords ? reverseBytesInWord(word) : word;
    }
    return arr;
  }
}

abstract class RpcClientInterface {
  dynamic rpc(String method, List<dynamic> params);
}

class BitcoinBlockSubmission {
  final RpcClientInterface rpcClient;

  BitcoinBlockSubmission(this.rpcClient);

  dynamic submitBlock(dynamic blockSubmission) {
    return rpcClient.rpc('submitblock', [blockSubmission]);
  }
}

class BitcoinBlockTemplate {
  final RpcClientInterface rpcClient;

  BitcoinBlockTemplate(this.rpcClient);

  Future<dynamic> getBlockTemplate() async {
    try {
      final result = await rpcClient.rpc('getblocktemplate', [
        {
          "rules": ["segwit"]
        }
      ]);
      return result;
    } catch (e) {
      return [];
    }
  }
}

class BitcoinRpcClient implements RpcClientInterface {
  final String rpcUrl;
  final String rpcUser;
  final String rpcPass;

  BitcoinRpcClient(this.rpcUrl, this.rpcUser, this.rpcPass);

  @override
  dynamic rpc(String method, [dynamic params]) async {
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
        Uri.parse('https://btc.getblock.io/d2f0f5e3-43e5-4919-8aec-dac1176b69a8/mainnet/'),
        headers: headers,
        body: data,
        encoding: utf8,
      );
      final jsonResponse = jsonDecode(response.body);

      if (jsonResponse['id'] != rpcId) {
        throw Exception('Invalid response id: got ${jsonResponse['id']}, expected $rpcId');
      } else if (jsonResponse['error'] != null) {
        throw Exception('RPC error: ${jsonResponse['error']}');
      }

      return jsonResponse['result'];
    } catch (e) {
      inspect(e);
      rethrow;
    }
  }
}
