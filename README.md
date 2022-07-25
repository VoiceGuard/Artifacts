# VoiceGuard Artifacts
This repository is used for presenting artifacts of VoiceGuard (#93 submission) for ACSAC 2022.


We include the experimental results and the code of the transparent proxy in different folders.


## RSSI_evaluation

This folder contains RSSI measurements from smartphone/smartwatch when issuing legitimate and malicious voice commands in three testbeds. The experimental results are used to generate Table 2, Table 3 and Table 4 in the paper. 

**analysis.ipynb**
>This file contains Python code that is used to calculate accuracy, precision, and recall from RSSI evaluation results. An example of the code execution is presented at the end of the file. To reproduce the experimental results, after the code is executed, follow the prompt to enter the choice of testbed, smart speaker, and deployment location. The results will be displayed and are consistent with that in Tables 2-4.



## Reproducing Steps

In the following, we describe the detailed steps to reproduce the voice command recognition and packet-holding performed in the transparent proxy. 

Here we use an Amazon Echo Dot smart speaker as a representitive example. We set up the transparent proxy on a laptop and connect it to a home WiFi router. The Amazon Echo Dot needs to be configured properly in the **Amazon Alexa**  App in order to connect to the same WiFi router.

### TCP redirection between the Amazon Echo Dot and the home WiFi router

In order to redirect the network traffic between the Echo Dot and the home WiFi router to go through our laptop (i.e., the transparent proxy), we use a python script to send forged arp responses to them. Specifically, we send forged arp responses to the Echo Dot to tell it that the IP address of the home WiFi router is at the MAC address of our laptop. On the other hand, we also send forged arp responses to the home WiFi router to tell it that the IP address of the Echo Dot is at the MAC address of our laptop. As a result, the traffic between them can be successfully redirected to the laptop. After that, we follow the instructions in [mitmproxy](https://docs.mitmproxy.org/stable/howto-transparent/) to further forward the redirected network packets to a local port on the laptop using the following steps

Enable IP forwarding

```
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
```

Disable ICMP redirects

```
sysctl -w net.ipv4.conf.all.send_redirects=0
```

Insert iptables rules

```
iptables -t nat -A PREROUTING -p tcp --src $echoDot -m multiport --dports 1:65535 --dst $wifiRouter  -j REDIRECT --to-port $listenPort
iptables -t nat -A PREROUTING -p tcp --src $wifiRouter -m multiport --dports 1:65535 --dst $echoDot  -j REDIRECT --to-port $listenPort 
```

The above procedures can be automated by a single python script in `code/redirect/redirect.py`. Before using this code, you must first enter the folder and install all the required python packages as specified in the `requirement.txt`. Then, you also need to configure the IP addresses and network interface in `delay.conf`. Specifically, please replace the interface name with yours (the interface name can be obtained by the `ifconfig` command) and use the correct IP addresses of the Echo Dot and the home WiFi router.

```
[common]
interface = wlp1s0 #proxy network interface
hub = 192.168.1.1 #home WiFi router address
device = 192.168.1.169 #Echo Dot address
port = 10000 #redirect port
```

Then, run the python script with sudo privilege and leave it running.

```
$ sudo -E python3 redirect.py
```

The script will prompt the sending of arp response as follows

```python
[+] Sent to 192.168.1.1 : 192.168.1.169 is-at 74:df:bf:9e:5f:b7
[+] Sent to 192.168.1.169 : 192.168.1.1 is-at 74:df:bf:9e:5f:b7
[+] Sent to 192.168.1.1 : 192.168.1.169 is-at 74:df:bf:9e:5f:b7
[+] Sent to 192.168.1.169 : 192.168.1.1 is-at 74:df:bf:9e:5f:b7
[+] Sent to 192.168.1.1 : 192.168.1.169 is-at 74:df:bf:9e:5f:b7
[+] Sent to 192.168.1.169 : 192.168.1.1 is-at 74:df:bf:9e:5f:b7
[+] Sent to 192.168.1.1 : 192.168.1.169 is-at 74:df:bf:9e:5f:b7
[+] Sent to 192.168.1.169 : 192.168.1.1 is-at 74:df:bf:9e:5f:b7
[+] Sent to 192.168.1.1 : 192.168.1.169 is-at 74:df:bf:9e:5f:b7
[+] Sent to 192.168.1.169 : 192.168.1.1 is-at 74:df:bf:9e:5f:b7
[+] Sent to 192.168.1.1 : 192.168.1.169 is-at 74:df:bf:9e:5f:b7
[+] Sent to 192.168.1.169 : 192.168.1.1 is-at 74:df:bf:9e:5f:b7
```

After successfully redirecting the packets, we run a proxy program to listen to the redirection port. Upon receiving any TCP connection request, the proxy program accepts it and retrieves the original destination IP address. Then a new connection between the proxy program and the original destination IP address is established. As a result, an originally TCP session between the Echo Dot and the home WiFi router is broken into two independent TCP connections. For each original TCP session between the Echo Dot and the WiFi router, we spawn 4 threads to handle the read and write of each TCP connection. Specifically, messages received from one side are put into a queue, which are then popped and sent out by the writing thread of the other side. We can inspect the content in the queue to know the information of each received message.


The proxy program is located in `code/proxy/passthrough.py`. You can run it by specifying the redirection port, which is set to 10000 by default.

```
$ python3 passthrough.py -p 10000
```

Use `-p` to specify the redirection port. Please make sure the port is not occupied by other program and matches the configuration in `code/redirect/delay.conf`. 


Then, the program will automatically prompt the length and time of received packets.

```python
voiceguard@voiceguard-dev:~/Desktop/code/proxy$ python3 passthrough.py
press any key at any time to start rssi verification...
07/24/2022 17:45:54.304 | start listening at port 10000
07/24/2022 17:46:35.713 | new session with ('54.239.29.0', 443) is established
07/24/2022 17:46:35.895 | application TLS record of [709] bytes to server at ('54.239.29.0', 443)
07/24/2022 17:46:35.933 | new session with ('54.167.177.211', 443) is established
07/24/2022 17:46:35.936 | session with ('54.239.29.0', 443) is getting terminated
07/24/2022 17:46:35.998 | session with ('54.239.29.0', 443) has been terminated
07/24/2022 17:46:36.120 | application TLS record of [63, 33] bytes to server at ('54.167.177.211', 443)
07/24/2022 17:46:36.125 | application TLS record of [653] bytes to server at ('54.167.177.211', 443)
07/24/2022 17:46:36.128 | application TLS record of [131] bytes to server at ('54.167.177.211', 443)
07/24/2022 17:46:36.146 | application TLS record of [73, 131, 188, 73, 131, 73, 131, 73, 131, 77, 33] bytes to server at ('54.167.177.211', 443)
07/24/2022 17:46:36.227 | IP address of avs server has been changed from UNKNOWN to 54.167.177.211.
```

The packet-holding function is disabled by default and you must press any key to enable the packet-holding function, as prompted in the first line. It displays lengths of TLS packets originated from the Echo Dot, which are labeled as *Application Data* in the unencrypted TLS record header. The proxy program automatically checks packet-length sequence of the new session establishment and retrieves the IP address of the AVS server if the packet-length sequence matches the known pattern, which is `63, 33, 653, 131, 73, 131, 188, 73, 131, 73, 131, 73, 131, 77, 33, 33`.


### Voice command recognition and packet holding

To hold the network packets, you can press any key to enable it. After that, the program will try to match the known traffic pattern of the first phase (as listed in Table 5 in the paper) and start packet-holding if recognizes a voice command. In the example below, `277,131,5861,75,138` matches the known pattern of the first phase. For the purpose of demonstrating the packet-holding process, here we delay the voice command for 5 seconds by default. 

```ruby
07/24/2022 17:48:11.481 | application TLS record of [277] bytes to server at ('54.167.177.211', 443)
07/24/2022 17:48:11.482 | application TLS record of [131, 5861, 75, 138, 1905] bytes to server at ('54.167.177.211', 443)
07/24/2022 17:48:11.494 | application TLS record of [5153, 113] bytes to server at ('54.167.177.211', 443)
07/24/2022 17:48:11.494 | match result: True
07/24/2022 17:48:11.494 | ---------------delay starts for 5 seconds---------------
```

For the RSSI verification process, the designed Andorid smartphone app is required to measure the Bluetooth RSSI value of the Echo Dot to determine the legitimacy of every voice command. To simplify the process of app installation and retrieving RSSI from the app, here we create a text file `rssi.txt` to store a non-positive value to simulate the measured RSSI value from the smartphone app. The proxy program reads this RSSI value and compares it with the pre-defined threshold, which is -6 by default. If the rssi value is larger than the threshold, the proxy program releases the voice command packets and sends them to the avs server. Otherwise, the proxy program discards the voice command. You can change the value in `rssi.txt` to test under different RSSI values.


Example of legitimate voice command when `-5` in `rssi.txt`

```ruby
07/24/2022 17:48:16.496 | Query takes 5.0019290447235107 seconds.
07/24/2022 17:48:16.496 | rssi verification succeed. Value is -5. Foward voice command packets to the AVS server.
07/24/2022 17:48:16.497 | ---------------delay ends for 5 seconds---------------
```


Example of malicious voice command when `-9` in `rssi.txt`

```ruby
07/24/2022 17:49:04.623 | Query takes 5.0020806789398193 seconds.
07/24/2022 17:49:04.623 | rssi verification failed. Value is -9. Discard voice command packets.
07/24/2022 17:49:04.623 | ---------------delay ends for 5 seconds---------------
```
