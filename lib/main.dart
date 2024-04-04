import 'dart:developer';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:flutter/material.dart';

import 'miner.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const MyHomePage(title: 'Flutter Demo Home Page'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});
  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

typedef CppMiner = Pointer<Utf8> Function(
  Pointer<Utf8> headerHex,
  Pointer<Utf8> targetHex,
);
typedef DartCppMiner = Pointer<Utf8> Function(
  Pointer<Utf8> headerHex,
  Pointer<Utf8> targetHex,
);

typedef CalculateHashNative = Pointer<Utf8> Function();
typedef CalculateHashDart = Pointer<Utf8> Function();

class _MyHomePageState extends State<MyHomePage> {
  bool mining = false;
  String headerHexMined = '';
  BlockTemplate? blockTemplate;

  List<String> logger = [];
  DynamicLibrary? nativeAddLib;
  void startMiner() async {
    setState(() {
      mining = !mining;
    });
    nativeAddLib ??= Platform.isAndroid
        ? DynamicLibrary.open('libminer_lib.so')
        : DynamicLibrary.process();
    final minerHeader =
        nativeAddLib?.lookupFunction<CppMiner, DartCppMiner>('minerHeader');

    final rpcClient = BitcoinRpcClient('rpcUrl', 'rpcUser', 'rpcPass');
    final miner = BitcoinMiner(rpcClient);
    blockTemplate = await rpcClient.getBlockTemplate();
    if (blockTemplate == null) {
      inspect('Failed to get block template');
      setState(() {
        mining = false;
      });
      return;
    }
    const coinbaseMessage = 'Mined by RafaelFernandes';
    const address = '1rafaeLAdmgQhS2i4BR1tRst666qyr9ut';
    final result = miner.getBlockHeaderHex(
        blockTemplate!, coinbaseMessage.codeUnits, address);
    inspect(result);
    if (result == null || minerHeader == null) {
      inspect('Failed to get block header');
      setState(() {
        mining = false;
      });
      return;
    }
    final result1 = minerHeader(result['headerHex']!.toNativeUtf8(),
        result['targetHex']!.toNativeUtf8());

    setState(() {
      headerHexMined = result1.toDartString();
      mining = false;
    });
  }

  void calcularHashsPorSegundo() {
    setState(() {
      mining = !mining;
    });
    nativeAddLib ??= Platform.isAndroid
        ? DynamicLibrary.open('libminer_lib.so')
        : DynamicLibrary.process();
    final calculateHashPerSeconds =
        nativeAddLib?.lookupFunction<CalculateHashNative, CalculateHashDart>(
            'calculateHashPerSeconds');
    final result1 = calculateHashPerSeconds!();

    setState(() {
      headerHexMined = result1.toDartString();
      mining = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: Text(widget.title),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            TextField(
              maxLines: 10,
              minLines: 5,
              readOnly: true,
              decoration: InputDecoration(
                labelText: 'Header Hex',
                border: const OutlineInputBorder(),
                filled: true,
                fillColor: Colors.grey[200],
                focusedBorder: OutlineInputBorder(
                  borderSide: const BorderSide(color: Colors.blue),
                  borderRadius: BorderRadius.circular(8),
                ),
              ),
              controller: TextEditingController(text: headerHexMined),
            ),
            Text(
              'Is mining: $mining',
              style: Theme.of(context).textTheme.headlineMedium,
            ),
            ElevatedButton(
              onPressed: startMiner,
              child:
                  mining ? const Text('Stop Miner') : const Text('Start Miner'),
            ),
            ElevatedButton(
              onPressed: calcularHashsPorSegundo,
              child: mining
                  ? const Text('Calculando')
                  : const Text('Calcular hashs por segundo'),
            ),
            const SizedBox(height: 40),
          ],
        ),
      ),
    );
  }
}
