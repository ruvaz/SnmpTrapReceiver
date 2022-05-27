# Simple Python based SNMP receiver


# How to use
Clone this Repo <br>

Make sure you have python and <b>pysnmp</b> installed <br>
```sh
pip install pysnmp
```

Change TrapAgentAddress='127.0.0.1'; to you server address or leave as local host if testing locally<br>

Change Port=162; to you server's listening port<br>

RUN 
```sh
python SNMPTrapReceiver.py
```
-> or for background execution: RUN nohup 

```sh
python SNMPTrapReceiver.py &
```
