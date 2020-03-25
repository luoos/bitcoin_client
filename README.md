# Bitcoin Client

## Run

```shell
# run 3 different instances (in 3 tabs)
cargo run -- -vv --p2p 127.0.0.1:6000 --api 127.0.0.1:7000
cargo run -- -vv --p2p 127.0.0.1:6001 --api 127.0.0.1:7001 -c 127.0.0.1:6000
cargo run -- -vv --p2p 127.0.0.1:6002 --api 127.0.0.1:7002 -c 127.0.0.1:6001

# use url endpoint to start mining
curl http://127.0.0.1:7000/miner/start?lambda=100000
curl http://127.0.0.1:7001/miner/start?lambda=100000
curl http://127.0.0.1:7002/miner/start?lambda=100000

# use url endpoint to check info (change port for different instance)
http://127.0.0.1:7000/blockchain/showheader # show headers of blockchain
http://127.0.0.1:7000/blockchain/showtx     # show transactions in blockchain
http://127.0.0.1:7000/blockchain/showstate  # show state of tip block
http://127.0.0.1:7000/mempool/showtx        # show transactions in mempool
```

```shell
# script (note that these scripts use specific ports)
./run.sh
./start_mining.sh

# kill
./kill.sh
```