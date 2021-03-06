# python version 1.0						DO NOT EDIT
#
# Generated by smidump version 0.4.8:
#
#   smidump -f python NIOBE-MIB

FILENAME = "mibs/NIOBE-MIB"

MIB = {
    "moduleName": "NIOBE-MIB",

    "NIOBE-MIB": {
        "nodetype": "module",
        "language": "SMIv2",
        "revisions": (
            {
                "date": "2019-10-29 20:00",
                "description":
                    """DSR mib version 1.2: Revision of version 1.0 NIOBE MIB, Niobe.mib.
Adds acquisitionRecoveryActive object

::=  {  giproducts  624  }

org           OBJECT IDENTIFIER
::=  {  iso  3  }

dod           OBJECT IDENTIFIER
::=  {  org  6  }

internet      OBJECT IDENTIFIER
::=  {  dod  1  }

mgmt       OBJECT IDENTIFIER
::=  {  internet  2  }

mib-2      OBJECT IDENTIFIER 
::=  {  mgmt      1  }

system       OBJECT IDENTIFIER 
::=  {  mib-2     1  }

private       OBJECT IDENTIFIER
::=  {  internet  4  }

enterprises   OBJECT IDENTIFIER
::=  {  private  1  }

giMIB         OBJECT IDENTIFIER
::=  {  enterprises  1166  }

giproducts    OBJECT IDENTIFIER
::=  {  giMIB  1  }   


-- the System group
-- Implementation of the System group is mandatory for all
-- systems.  If an agent is not configured to have a value
-- for any of these variables, a string of length 0 is
-- returned.

sysDescr OBJECT-TYPE
SYNTAX        DisplayString
MAX-ACCESS    read-only
STATUS        current
DESCRIPTION
    """,
            },
        ),
    },

    "imports": (
        {"module": "SNMPv2-SMI", "name": "MODULE-IDENTITY"},
        {"module": "SNMPv2-SMI", "name": "OBJECT-TYPE"},
        {"module": "SNMPv2-SMI", "name": "IpAddress"},
        {"module": "SNMPv2-SMI", "name": "TimeTicks"},
        {"module": "SNMPv2-SMI", "name": "NOTIFICATION-TYPE"},
        {"module": "SNMPv2-TC", "name": "DisplayString"},
    ),

    "nodes": {
        "sysUpTime": {
            "nodetype": "scalar",
            "moduleName": "NIOBE-MIB",
            "oid": "0.3",
            "status": "current",
            "syntax": {
                "type": {"module": "SNMPv2-SMI", "name": "TimeTicks"},
            },
            "access": "readonly",
            "description":
                """The time (in hundredths of a second) since the
network management portion of the system was last
re-initialized.""",
        },  # scalar
        "sysContact": {
            "nodetype": "scalar",
            "moduleName": "NIOBE-MIB",
            "oid": "0.4",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "OctetString",
                    "ranges": [
                        {
                            "min": "0",
                            "max": "255"
                        },
                    ],
                    "range": {
                        "min": "0",
                        "max": "255"
                    },
                },
            },
            "access": "readwrite",
            "description":
                """The textual identification of the contact person
for this managed node, together with information
on how to contact this person.""",
        },  # scalar
        "sysName": {
            "nodetype": "scalar",
            "moduleName": "NIOBE-MIB",
            "oid": "0.5",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "OctetString",
                    "ranges": [
                        {
                            "min": "0",
                            "max": "255"
                        },
                    ],
                    "range": {
                        "min": "0",
                        "max": "255"
                    },
                },
            },
            "access": "readwrite",
            "description":
                """An administratively-assigned name for this
managed node.""",
        },  # scalar
        "sysLocation": {
            "nodetype": "scalar",
            "moduleName": "NIOBE-MIB",
            "oid": "0.6",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "OctetString",
                    "ranges": [
                        {
                            "min": "0",
                            "max": "255"
                        },
                    ],
                    "range": {
                        "min": "0",
                        "max": "255"
                    },
                },
            },
            "access": "readwrite",
            "description":
                """The physical location of this node (e.g.,
'telephone closet, 3rd floor').""",
        },  # scalar
        "sysServices": {
            "nodetype": "scalar",
            "moduleName": "NIOBE-MIB",
            "oid": "0.7",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Integer32",
                    "ranges": [
                        {
                            "min": "0",
                            "max": "127"
                        },
                    ],
                    "range": {
                        "min": "0",
                        "max": "127"
                    },
                },
            },
            "access": "readonly",
            "description":
                """A value which indicates the set of services that
this entity primarily offers.

The value is a sum.  This sum initially takes the
value zero, Then, for each layer, L, in the range
1 through 7, that this node performs transactions
for, 2 raised to (L - 1) is added to the sum.  For
example, a node which performs primarily routing
functions would have a value of 4 (2^(3-1)).  In
contrast, a node which is a host offering
application services would have a value of 72
(2^(4-1) + 2^(7-1)).  Note that in the context of
the Internet suite of protocols, values should be
calculated accordingly:

layer  functionality
1  physical (e.g., repeaters)
2  datalink/subnetwork (e.g., bridges)
3  internet (e.g., IP gateways)
4  end-to-end  (e.g., IP hosts)
7  applications (e.g., mail relays)

For systems including OSI protocols, layers 5 and
6 may also be counted.""",
        },  # scalar
    },  # nodes

}
