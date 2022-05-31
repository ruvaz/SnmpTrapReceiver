from pysnmp.smi import builder, view, compiler, rfc1902

# Assemble MIB browser
mibBuilder = builder.MibBuilder()
mibViewController = view.MibViewController(mibBuilder)
compiler.addMibCompiler(
    mibBuilder, sources=['file:///usr/.'])

# Pre-load MIB modules that define objects we receive in TRAPs
mibBuilder.loadModules('')

# This is what we would get in a TRAP PDU
varBinds = [
    ('1.3.6.1.2.1.1.3.0', 12345),
    ('1.3.6.1.6.3.1.1.4.1.0', '1.3.6.1.6.3.1.1.5.2'),
    ('1.3.6.1.6.3.18.1.3.0', '0.0.0.0'),
    ('1.3.6.1.6.3.18.1.4.0', ''),
    ('1.3.6.1.6.3.1.1.4.3.0', '1.3.6.1.4.1.20408.4.1.1.2'),
    ('1.3.6.1.2.1.1.1.0', 'my system')
]

# Pass raw var-binds through MIB browser
varBinds = [
    rfc1902.ObjectType(rfc1902.ObjectIdentity(
        x[0]), x[1]).resolveWithMib(mibViewController)
    for x in varBinds
]

for varBind in varBinds:
    print(varBind.prettyPrint())


builder = engine.getMibBuilder()
# Make ./mibs available to all OIDs that are created
# e.g. with "MIB-NAME-MIB::identifier"
builder.addMibSources(builder_module.DirMibSource(
    os.path.join(HERE, 'mibs')
))
