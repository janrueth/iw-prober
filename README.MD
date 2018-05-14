# IW-Prober

We built this tool for our TMA 2018 Paper: "Demystifying TCP Initial Window Configurations of Content Distribution Networks"
It enables to measure TCP Initial Congestion Windows.

## Building

### Clone repository
 ```
 $ cd $GOPATH/src/github.com/Eichhoernchen/
 $ git clone https://github.com/Eichhoernchen/iw-prober.git
 ```


### Fetch dependencies
 ```
 $ cd $GOPATH/src/github.com/Eichhoernchen/
 $ go get -t .
 ```

### Create
 ```
 $ cd $GOPATH/src/github.com/Eichhoernchen/
 $ go build
 ```

## Running
The tool transparently takes a line-wise json from stdin, it requires the following fields to be present:
 
```
 {"mss": INTEGER, "url": "http://hostname/path/object"}
```

 With the `mss` being the Maximum Segment Size that should be used to probe the supplied URL.
 And `url` being the URL that should be probed for its TCP IW.
 Please note that regardless of the port or schema, the scanner will initiate a HTTP/TCP connection on the command line parameter specified port.

 There are several command line arguments that you should know about:

```
  -conn-timeout int
    	Timeout in seconds for each connection (default 10)
  -dev string
    	The device to use
  -dst_port int
    	Destination port (default 80)
  -gw string
    	The gateway to use, if not VPN
  -parallel int
    	Number of parallel pacing estimations (default 10)
  -pktrate int
    	How many packets should we allow per second? [default shared to roughly 1 Mbit] (default 100)
  -profile string
    	Should open pprof on port 6060 on this ip
  -source-ip string
    	Set the source IP
  -src-mac string
    	The source mac  if not VPN
  -vpn
    	Should this use a VPN (no L2 created)
```

Not all are mandatory, for running the tool without a VPN you should at least set the `-dev`, `-gw`, `-source-ip` and `-src-mac`.
For running the tool with a VPN you should set: `-dev`, `-vpn` `-source-ip` 

Please note that the tool will run in parallel to the regular TCP stack of your OS.
This has the implication that your OS will see a lot of packets that it cannot map to a TCP connection causing it to send RST packets.

You should, for the duration of the measurement drop these RST packets or instruct your OS not to send any.

Dropping RST packets can for example be done using iptables:
```
iptables -A OUTPUT -p tcp -m tcp --destination-port ${PORT} -s ${SRC_IP} --tcp-flags RST,RST RST,RST -j DROP
```
Please note the variables.

Further your system is probably configured to reassemble TCP packets, you should disable any optimizations with this regard using:

```
echo "Turning Large Receive Offloading off"
sudo ethtool -K $DEV lro off
echo "Turning Generic Receieve Offloading off"
sudo ethtool -K $DEV gro off
echo "Turning Generic Segmentation Offloading off"
sudo ethtool -K $DEV gso off
echo "Turning TCP Segmentation Offloading off"
sudo ethtool -K $DEV tso off
```

Please note the $DEV parameter which is your physical ethernet device.

## Output

Once the tool has probed the URL, it will emit a json to stdout containing the json it read from stdin + a `results` field:
The field contains the DNS resolution (`dns`), as well as `connection` field which keeps track of the connection information.
More specifically, the IW (in bytes) can be calculated from `.results.connection.data.end_of_data - .results.connection.data.start_of_data`.
Further, the observed MSS (largest observed segment size) is available via: `.results.connection.data.observed_mss`
All individually received segments (seq_num, len) are made available via the array: `.results.connection.data.segments`


