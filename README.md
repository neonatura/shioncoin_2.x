share-coin
==========

<h4>Part of the Share Library Suite.</b>

<h2>Quick Instructions</h2>

64-bit: Add '--libdir=/usr/local/lib64' as configure command-line option

Building the share library:
<i><small><pre>
  git clone https://github.com/neonatura/share
  cd share
  ./configure
  make
  make install
</pre></small><i>

Building the share-coin programs:
<i><small><pre>
  git clone https://github.com/neonatura/share-coin
  cd share-coin
  ./configure --with-libshare=../share
  make
  make install
</pre></small><i>

The binaries can be found under src/share-coin as "shcoin" and "shcoind". Performing a 'make install' will install these programs into the bin and sbin directories respectively. The "shcoin" program must be ran as the same user as the "shcoind" daemon. The daemons supplied with the share library suite (shared, shlogd, shfsyncd) and base libraries can be installed by running 'make install' in the share-coin/share/build directory built from the instructions above. 

When installed on a unix-like systems that supports the traditional /etc/init.d/rc.d/ hierarchy a 'shcoind' daemon will be registered with the system to load upon startup as the root user. 
Note: The "shcoin" client utility program must be ran as the same user as the 'shcoind' daemon.

<h3>Stratum + USDe Coin Service</h3>
A stratum server for the USDe virtual currency is provided in this library. The server is embedded into the usde coin server in the program "shcoind". The "shcoin" program is provided to perform RPC commands against the coin server.

Note: No additional programs from the share library suite is required in order to run the coin+stratum service. The C share library is staticly linked against the coin service, and a 'make install' is not required to run the program.


<h3>Stratum Protocol Template</h3>
<br>Command: mining.ping
<br>Description: Verify or measure server response time.
<br>Example Request: {"method":"mining.ping","id":1,"params":[]}
<br>Example Response: {"id":1,"error":null,"result":null}
<br>
<br>Command: mining.shares
<br>
<br>Command: mining.get_transactions
<br>
<br>Command: mining.info
<br>
<br>Command: mining.authorize
<br>
<br>Command: mining.submit
<br>
<br>Command: mining.subscribe
<br>
<br>Command: block.info[mode,hash]
<br>Description: Obtain block and transaction info from a block hash.
<br>
<br>Command: account.info[account,pkey]
<br>Description: Obtain account credentials by name and account key.
<br>
<br>Command: account.create[label]
<br>
<br>Command: account.transactions[amount,pkey,duration]
<br>
<br>Command: account.address[hash]
<br>
<br>Command: account.secret[addr,pkey]
<br>
<br>Command: account.import[account,priv addr]
<br>
<br>Command: account.transfer[account,pkey,addr,amount]


<h3>Build Dependencies</h3>

The c++ boost shared library is required.  To be specific, the "system", "filesystem", "program_options", and "thread" boost libraries. The "shcoind" and "shcoin" programs are the only sharelib program that link against boost libraries.
To install on linux run 'yum install libboost*' or 'apt-get install libboost*'.

The 'openssl version 1.0.1g' distribution has been included in the directory '/depend/openssl-1.0.1g'. This version will automatically be compiled and linked against the shcoind and shcoin programs.

shcoin - Client Utility Program
===============================

Run "shcoin help" to list command-line arguments:

<small>
addmultisigaddress <nrequired> <'["key","key"]'> [account]

backupwallet <destination>

createrawtransaction [{"txid":txid,"vout":n},...] {address:amount,...}

decoderawtransaction <hex string>

dumpprivkey <usdeaddress>

getaccount <usdeaddress>

getaccountaddress <account>

getaddressesbyaccount <account>

getbalance [account] [minconf=1]

getblock <hash>

getblockcount

getblockhash <index>

getblocktemplate [params]

getconnectioncount

getdifficulty

getinfo

getmininginfo

getnetworkhashps [blocks]

getnewaddress [account]

getpeerinfo

getrawmempool

getrawtransaction <txid> [verbose=0]

getreceivedbyaccount <account> [minconf=1]

getreceivedbyaddress <usdeaddress> [minconf=1]

gettransaction <txid>

getwork [data]

getworkex [data, coinbase]

help [command]

importprivkey <usdeprivkey> [label]

keypoolrefill

listaccounts [minconf=1]

listreceivedbyaccount [minconf=1] [includeempty=false]

listreceivedbyaddress [minconf=1] [includeempty=false]

listsinceblock [blockhash] [target-confirmations]

listtransactions [account] [count=10] [from=0]

listunspent [minconf=1] [maxconf=999999]

move <fromaccount> <toaccount> <amount> [minconf=1] [comment]

sendfrom <fromaccount> <tousdeaddress> <amount> [minconf=1] [comment] [comment-to]

sendmany <fromaccount> {address:amount,...} [minconf=1] [comment]

sendrawtransaction <hex string>

sendtoaddress <usdeaddress> <amount> [comment] [comment-to]

setaccount <usdeaddress> <account>

setmininput <amount>

settxfee <amount>

signmessage <usdeaddress> <message>

signrawtransaction <hex string> [{"txid":txid,"vout":n,"scriptPubKey":hex},...] [<privatekey1>,...] [sighashtype="ALL"]

stop

validateaddress <usdeaddress>

verifymessage <usdeaddress> <signature> <message>
</small>

The shcoind and shcoin program will write data to the /var/lib/share/usde/ directory. The "usde.conf" configuration file is only present in this directory in order to supply the automatically generated RPC user/pass. 
