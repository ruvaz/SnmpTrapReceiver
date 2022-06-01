#!/usr/bin/python
# python snmp trap receiver
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.smi import builder, view, compiler, rfc1902
import logging
import sqlite3
from sys import platform
import sys
import datetime


# Get Database file by SO
if platform == "win32":
    traps_db = 'c:/bin/traps_data.db'
else:
    traps_db = '/var/log/jenkins/project_csv_files/obtain_encryption_mode_status/traps_data.db'


def save_to_db_trap(traps={}):
    '''Function to save the trap to the database'''
    conn = sqlite3.connect(traps_db)
    cursor = conn.cursor()

    timestamp_string = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S%z")

    for key, values in traps.items():
        for oid in values:
            params = (timestamp_string, key, oid[0], oid[1])
            cursor.execute(
                "INSERT INTO traps_catcher('date','ip','oid','value') VALUES(?, ?, ?,?)", params)

    conn.commit()
    # LED Data Insertion Successful
    conn.close()


# Assemble MIB browser
mibBuilder = builder.MibBuilder()
mibViewController = view.MibViewController(mibBuilder)
compiler.addMibCompiler(
    mibBuilder, sources=['pymib'])

# Pre-load MIB modules that define objects we receive in TRAPs
mibBuilder.loadModules('BCS-IDENT-MIB', 'NIOBE-MIB', 'BNC-MIB',
                       'MOD-SYS-TRAPS-MIB')

snmpEngine = engine.SnmpEngine()

# Trap listerner address
# This code wait for a parameter for IP address of this receiver
TrapAgentAddress = sys.argv[1]  # '10.45.77.164'
Port = 162


logging.basicConfig(filename='received_traps.log', filemode='a',
                    format='%(asctime)s - %(message)s', level=logging.INFO)
logging.info("Agent is listening SNMP Trap on " +
             TrapAgentAddress+" , Port : " + str(Port))
logging.info(
    '---------------------------------------------------------------')


print("\nAgent is listening SNMP Trap on " +
      TrapAgentAddress+" , Port : " + str(Port)+"\n")

config.addTransport(
    snmpEngine,
    udp.domainName + (1,),
    udp.UdpTransport().openServerMode((TrapAgentAddress, Port))
)

# Configure community here
# config.addV1System(snmpEngine, 'public', 'public')
config.addV1System(snmpEngine, 'public-read', 'public')


def cbFun(snmpEngine, stateReference, contextEngineId, contextName,
          varBinds, cbCtx):
    '''Function to handle TRAPs'''

    # Get IP address of the trap sender
    execContext = snmpEngine.observer.getExecutionContext(
        'rfc3412.receiveMessage:request'
    )
    ipDevice, port = execContext['transportAddress']

    print("-------- Received new Trap message from: % s  --------" % ipDevice)
    logging.info(
        "-------- Received new Trap message from: %s --------" % ipDevice)

    # Get the trap OID with Mib
    varBinds = [
        rfc1902.ObjectType(rfc1902.ObjectIdentity(
            x[0]), x[1]).resolveWithMib(mibViewController)
        for x in varBinds
    ]

    traps = {}
    list_traps = []
    # Get the OID and value of the trap
    for name, val in varBinds:
        logging.info('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
        print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
        list_traps.append((name.prettyPrint(), val.prettyPrint()))
        traps[ipDevice] = list_traps

    save_to_db_trap(traps)
    logging.info("-------- End of Incoming Trap --------\n")
    print("-------- End of Incoming Trap --------\n")


# Register SNMP Application at the SNMP engine
ntfrcv.NotificationReceiver(snmpEngine, cbFun)
# Run I/O dispatcher which would receive queries
snmpEngine.transportDispatcher.jobStarted(1)

try:
    snmpEngine.transportDispatcher.runDispatcher()
except:
    snmpEngine.transportDispatcher.closeDispatcher()
    raise
