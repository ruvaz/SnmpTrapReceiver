#!/usr/bin/python
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.smi import builder, view, compiler, rfc1902
import logging
import sys

import utils

ip_to_report = ['10.11.102.16', '10.11.99.104']

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

# logger configuration
logger = logging.getLogger('SNMP_Trap_Receiver')
utils.init_logging(logger, "INFO", log_file="snmp_trap_receiver.log")

logger.info("Agent is listening SNMP Trap on " +
            TrapAgentAddress + " , Port : " + str(Port))
logger.info(
    '---------------------------------------------------------------')

print("\nAgent is listening SNMP Trap on " +
      TrapAgentAddress + " , Port : " + str(Port) + "\n")

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

    print("-------- Receive new Trap message from: %s  --------" % ipDevice)
    logger.info(
        "-------- Receive new Trap message from: %s --------" % ipDevice)

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
        logger.info('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
        print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
        list_traps.append((name.prettyPrint(), val.prettyPrint()))
        traps[ipDevice] = list_traps

    utils.save_to_db_trap(traps)
    if ipDevice in ip_to_report:
        utils.send_email_traps(ipDevice, traps[ipDevice])

    logger.info("-------- End of Incoming Trap --------\n")
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
