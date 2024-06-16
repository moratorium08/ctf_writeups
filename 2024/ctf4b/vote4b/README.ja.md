# vote4b

Web3の世界へようこそ！

Web3とSolidityの基礎については、[Solidityの公式ドキュメント](https://soliditylang.org/)などを参考にしてください。

## ローカルでのテスト

ローカルでSolidityコントラクトの動作を試す方法はいくつかあります。

ここでは、標準的なフレームワークである[foundry](https://book.getfoundry.sh/)を例として説明します。Foundryを使ったことがない人は、[インストールガイド](https://book.getfoundry.sh/getting-started/installation)に従ってインストールしましょう。

### テストネットワークの構築

実際のEthereumネットワークのようにオープンな場所で試すためにはGasと呼ばれる手数料が掛かります。Foundryに付属する[anvil](https://book.getfoundry.sh/reference/anvil/)というコマンドを使うと、あなただけのネットワークをローカルに構築できます。

```
$ anvil
```

コマンドを実行すると、10個のアカウントのアドレスと秘密鍵が表示されます。これらはすべてあなたが所有するアカウントで、初期状態では10000ethを保有しています。（残念ながらテストネットワークなので価値はありません。）なお、`deploy/config.yaml`に記載されている通り、リモートではあなたは1ethしか保有していない点に注意してください。

Web3の問題では、主に被害者と攻撃者の2つのアカウントが必要なので、適当に選んだ2つのアカウントのアドレスと秘密鍵をメモしておきましょう。

また、Web3クライアントがネットワークとやりとりするための、RPCと呼ばれるエンドポイントが作成されます。これは`anvil`の出力の最後に記載されており、通常は`http://localhost:8545/`です。

```
Listening on 127.0.0.1:8545
```

### プロジェクトの初期化

問題のSolidityファイルをデプロイして試すため、[プロジェクトを作ります](https://book.getfoundry.sh/reference/forge/forge-init)。例えば以下のようなコマンドで`vote4b`という名前のプロジェクトが作成されます。

```
$ forge init vote4b
```

標準では`Counter`というサンプルコントラクトが作られていますが、今回は使わないのですべて削除しましょう。

```
$ rm src/Counter.sol test/Counter.sol script/Counter.s.sol
```

### 依存関係のインストール

配布ファイルの`src/Ballot.sol`を見ると、何やら外部ライブラリをインストールしています。

```sol
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { ERC721 } from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
```

これらは[OpenZeppelin Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts)と呼ばれる、最も有名なライブラリです。このライブラリは、Web3でよく使われる機能や、標準化された規格の安全な実装を提供してくれます。

ライブラリを[インストールしましょう](https://book.getfoundry.sh/reference/forge/forge-install)。（プロジェクトに変更があった場合、先に`git commit`で変更をコミットしないとインストールできません。）

```
$ git commit -a
$ forge install openzeppelin/openzeppelin-contracts
```

### コントラクトのデプロイ

配布ファイルの`src`以下にある`.sol`ファイルをすべて、作ったプロジェクトの`src`フォルダにコピーしてください。今回の問題は`Setup.sol`ファイルに記述された`Setup`コントラクトが起点となります。そのため、`Setup`コントラクトを[作成します](https://book.getfoundry.sh/reference/forge/forge-create)。

Setupコントラクトは攻撃対象なので、先ほどあなたが選んだ被害者のアカウント情報を使ってください。

```
$ forge create --rpc-url <RPCのURL> --private-key <被害者の秘密鍵> src/Setup.sol:Setup
```

コントラクトが問題なくコンパイル・作成できたら、出力に"Deployed to"という項目があるはずです。

```
Deployed to: 0xXXXXXXXX....XXXXXXXX
```

この16進数が、あなたのデプロイした`Setup`コントラクトのアドレスですので、メモしておきましょう。

### 問題概要

さて、コントラクトがデプロイできたら、ソースコードを読んでコントラクトの意味を理解しましょう。`Ballot.sol`は、[ERC721](https://ethereum.org/en/developers/docs/standards/tokens/erc-721/)（NFT; Non-Fungible Token）という規格を利用して、投票用紙に似た仕組みを実装しています。投票用紙の所有者の明確化や、多重投票の防止などをどのように実現しているのか、ソースコードや[Solidityの言語仕様](https://docs.soliditylang.org/en/v0.8.26/)、またOpenZeppelinの[ERC721の仕様](https://docs.openzeppelin.com/contracts/4.x/erc721)などを読んで確認しましょう。

`deploy/verifier.py`に記載されていますが、今回の目標は`Setup`コントラクトの`isSolved`関数にtrueを返させることです。

```
function isSolved() public view returns (bool) {
  return ballot.votes(address(this)) >= 10;
}
```

どうやら、`Setup`コントラクトに10票以上を投票することが目標のようです。

### Exploitの作成

Exploitのテンプレートコードが`template/Exploit.s.sol`に用意されています。これは[`forge script`](https://book.getfoundry.sh/reference/forge/forge-script)用に書かれています。このコードを`vote4b`プロジェクトの`script`フォルダにコピーしましょう。

`Script`では、まず`setUp`関数が呼ばれます。
テンプレートのコードでは、`Setup`コントラクトと攻撃者のアカウントのみをセットアップしているので、適宜アドレスと鍵を設定してください。
```sol
  function setUp() public {
    chall = Setup(/* Setup Contract's Address */);
    solver = vm.createWallet(/* Attacker's Private Key */);
  }
```

次に、`run`関数が呼ばれます。テンプレートのコードでは、[`startBroadcast`](https://book.getfoundry.sh/cheatcodes/start-broadcast)を呼び出して、以降の処理をすべて攻撃者のアカウントで実行するように設定しています。例としてSetupコントラクトが保有している`ballot`を参照し、その`votes`変数を確認しています。最後に`chall.isSolved()`がtrueであることを要求しているので、問題が解けるまでトランザクションが送られることはありません。
```sol
  function run() public {
    vm.startBroadcast(solver.privateKey);

    // Your exploit goes here
    Ballot ballot = chall.ballot();
    uint256 n = ballot.votes(address(chall));

    require(chall.isSolved(), "Not solved");
  }
```

Exploitを試すには、[`forge script`コマンド](https://book.getfoundry.sh/reference/forge/forge-script)を使います。例えば以下のコマンドで`Exploit.s.sol`の`Exploit`コントラクトを試せます。

```
$ forge script --rpc-url <RPCのURL> --private-key <攻撃者の秘密鍵> --broadcast script/Exploit.s.sol:Exploit
```

Solidityの言語仕様書や一般的な脆弱性について調べ、投票結果を操るExploitを書きましょう。

## Dockerでのテスト

リモートと同じ環境をdockerで再現するには、以下のコマンドを利用できます。

```
$ docker build . -t vote4b
$ docker run --rm -p 8000:8000 vote4b
```

Webブラウザで http://localhost:8000/start にアクセスすると、ランダムな16進数のIDを含む4つのエンドポイントが得られます。（このIDを失った場合はインスタンスを再度建て直してください。）

1. `/(Your_ID)/rpc`
   RPCネットワークのエンドポイント
2. `/(Your_ID)/info`
   コントラクトとアカウントの情報を取得するエンドポイント
3. `/(Your_ID)/reset`
   テストネットワークの状態をリセットするエンドポイント
4. `/(Your_ID)/flag`
   問題が解けている場合にフラグを表示するエンドポイント

まず、 http://localhost:8000/(Your_ID)/info にアクセスすると、以下の3つの情報が得られます。

1. `level_contract_address`
   Ethereumのテストネットワーク上にデプロイされたSetupコントラクト（`src/Setup.sol`）のアドレス
2. `user_private_key`
   あなたのアカウントの秘密鍵
3. `user_address`
   あなたのアカウントのアドレス

forgeコマンドに渡すRPCのURLを変更し、上記の情報をあなたのExploitコントラクトに組み込むことで、テストネットワーク上で問題を解くことができます。
`isSolved`関数がtrueを返したら、`/(Your_ID)/flag`にアクセスしてフラグが獲得できることを確認しましょう。

## リモートでの動作

Ethereumネットワーク上のすべてのコントラクトやトランザクションは、すべてのユーザに公開されます。
誰かにあなたのExploitコントラクトを盗まれることを防ぐため、実際の問題サーバではユーザごとにEthereumネットワークを分離しています。

問題URLにアクセスして「Spawn instance」ボタンを押すことで、10分間だけ有効なあなただけのネットワークを構築できます。
得られたURL（例えば `http://NGwEtghVvYWJoUfm:ZrlngjpJoGcNzSAX@vote4b.beginners.seccon.games:63607` ）は、先ほどまでの`localhost:8000`と同じ役割を果たします。
`/start`エンドポイントにアクセスしてテストネットワークを作り、Exploitを送る先のRPCやコントラクトのアドレスなどを変更してフラグを得ましょう。
