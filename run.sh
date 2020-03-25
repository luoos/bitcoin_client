cargo build --release
cargo run --release -- -vv --p2p 127.0.0.1:6000 --api 127.0.0.1:7000 &
sleep 1
cargo run --release -- -vv --p2p 127.0.0.1:6001 --api 127.0.0.1:7001 -c 127.0.0.1:6000 &
sleep 1
cargo run --release -- -vv --p2p 127.0.0.1:6002 --api 127.0.0.1:7002 -c 127.0.0.1:6001 &