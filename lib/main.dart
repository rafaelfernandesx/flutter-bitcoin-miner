import 'dart:developer';

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

class _MyHomePageState extends State<MyHomePage> {
  bool mining = false;

  List<String> logger = [];

  void startMiner() async {
    setState(() {
      mining = !mining;
    });
    String rpcUrl = 'http://localhost:18443';
    String rpcUser = 'user';
    String rpcPass = 'pass';
    final blockTemplate = BitcoinBlockTemplate(BitcoinRpcClient(rpcUrl, rpcUser, rpcPass));
    final blockSubmission = BitcoinBlockSubmission(BitcoinRpcClient(rpcUrl, rpcUser, rpcPass));
    final miner = BitcoinMiner(blockTemplate, blockSubmission);

    const coinbaseMessage = 'Mined by RafaelFernandes';
    const address = '1rafaeLAdmgQhS2i4BR1tRst666qyr9ut';
    const extranonceStart = 0;
    const timeout = 10; // time in seconds to get a new blcktemplate

    bool mined = false;

    while (mined == false && mining == true) {
      final result = await miner.mineBlock(coinbaseMessage.codeUnits, address, extranonceStart, timeout: timeout);
      if (result == null || result['nonce'] == null) {
        inspect(result);
        mined = true;
        break;
      } else {
        setState(() {
          logger.add('Total hashs: ${result['hashRateCount']} in $timeout seconds, height: ${result['height']}');
        });
      }
    }
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
            Expanded(
              child: ListView.builder(
                shrinkWrap: true,
                itemCount: logger.length,
                itemBuilder: (context, index) {
                  return Text(logger[index]);
                },
              ),
            ),
            Text(
              'Is mining: $mining',
              style: Theme.of(context).textTheme.headlineMedium,
            ),
            ElevatedButton(
              onPressed: startMiner,
              child: mining ? const Text('Stop Miner') : const Text('Start Miner'),
            )
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () {},
        tooltip: 'Increment',
        child: const Icon(Icons.add),
      ),
    );
  }
}
