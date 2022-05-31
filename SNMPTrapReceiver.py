# python snmp trap receiver
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.smi import builder, view, compiler, rfc1902
import logging

# Assemble MIB browser
mibBuilder = builder.MibBuilder()
mibViewController = view.MibViewController(mibBuilder)
compiler.addMibCompiler(
    mibBuilder, sources=['file:///usr/BNC-MIB.py'])

# Pre-load MIB modules that define objects we receive in TRAPs
mibBuilder.loadModules('BNC-MIB')


snmpEngine = engine.SnmpEngine()

# Trap listerner address
TrapAgentAddress = '10.45.77.164'
Port = 162


logging.basicConfig(filename='received_traps.log', filemode='w',
                    format='%(asctime)s - %(message)s', level=logging.INFO)
logging.info("Agent is listening SNMP Trap on " +
             TrapAgentAddress+" , Port : " + str(Port))
logging.info(
    '--------------------------------------------------------------------------')


print("Agent is listening SNMP Trap on " +
      TrapAgentAddress+" , Port : " + str(Port))

config.addTransport(
    snmpEngine,
    udp.domainName + (1,),
    udp.UdpTransport().openServerMode((TrapAgentAddress, Port))
)

# Configure community here
config.addV1System(snmpEngine, 'my-area', 'public')


def cbFun(snmpEngine, stateReference, contextEngineId, contextName,
          varBinds, cbCtx):
    print("--------Received new Trap message--------")
    logging.info("--------Received new Trap message--------")

    varBinds = [
        rfc1902.ObjectType(rfc1902.ObjectIdentity(
            x[0]), x[1]).resolveWithMib(mibViewController)
        for x in varBinds
    ]

    # Print
    for name, val in varBinds:
        logging.info('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
        print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))

    logging.info("==== End of Incoming Trap ====")


ntfrcv.NotificationReceiver(snmpEngine, cbFun)

snmpEngine.transportDispatcher.jobStarted(1)

try:
    snmpEngine.transportDispatcher.runDispatcher()
except:
    snmpEngine.transportDispatcher.closeDispatcher()
    raise
