# python version 1.0						DO NOT EDIT
#
# Generated by smidump version 0.4.8:
#
#   smidump -f python MOD-SYS-TRAPS-MIB

FILENAME = "mibs/MOD-SYS-TRAPS-MIB"

MIB = {
    "moduleName": "MOD-SYS-TRAPS-MIB",

    "MOD-SYS-TRAPS-MIB": {
        "nodetype": "module",
        "language": "SMIv2",
        "organization":
            """Motorola Connected Home Solutions""",
        "contact":
            """Motorola Technical Response Center
Inside USA     1-888-944-HELP (1-888-044-4357)
Outside USA    1-215-323-0044
TRC Hours:
Monday through Friday 8am - 7pm Eastern Standard Time
Saturdays            10am - 5pm Eastern Standard Time""",
        "description":
            """The MIB module for the modular system common trap objects.This 
MIB is based on the BCS Traps MIB and is intended to produce 100%
compatible traps. The structure is also intended to remain identical
to the BCS traps MIB except that the tables are controlled by 
rowStatus objects and are not limited to 4 receivers.""",
        "revisions": (
            {
                "date": "2006-11-08 20:00",
                "description":
                    """[Revision added by libsmi due to a LAST-UPDATED clause.]""",
            },
        ),
        "identity node": "modSysTraps",
    },

    "imports": (
        {"module": "SNMPv2-SMI", "name": "IpAddress"},
        {"module": "SNMPv2-SMI", "name": "TimeTicks"},
        {"module": "SNMPv2-SMI", "name": "OBJECT-TYPE"},
        {"module": "SNMPv2-SMI", "name": "Integer32"},
        {"module": "SNMPv2-SMI", "name": "MODULE-IDENTITY"},
        {"module": "SNMPv2-TC", "name": "RowStatus"},
        {"module": "SNMPv2-TC", "name": "DisplayString"},
        {"module": "SNMPv2-TC", "name": "TEXTUAL-CONVENTION"},
        {"module": "", "name": "bcs"},
    ),

    "typedefs": {
        "ConfigChangeState": {
            "basetype": "Enumeration",
            "status": "current",
            "staged": {
                "nodetype": "namednumber",
                "number": "1"
            },
            "applied": {
                "nodetype": "namednumber",
                "number": "2"
            },
            "saved": {
                "nodetype": "namednumber",
                "number": "3"
            },
            "description":
                """Represents the current state of a configuration change""",
        },
        "ConfigChangeAction": {
            "basetype": "Enumeration",
            "status": "current",
            "waitingRetune": {
                "nodetype": "namednumber",
                "number": "1"
            },
            "waitingSave": {
                "nodetype": "namednumber",
                "number": "2"
            },
            "waitingReboot": {
                "nodetype": "namednumber",
                "number": "3"
            },
            "description":
                """Represents the action required to instantiate configuration change.""",
        },
    },  # typedefs

    "nodes": {
        "modSysTraps": {
            "nodetype": "node",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3",
            "status": "current",
        },  # node
        "modSysTrapElements": {
            "nodetype": "node",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.1",
        },  # node
        "trapIdentifier": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.1.1",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Integer32",
                    "ranges": [
                        {
                            "min": "1",
                            "max": "2147483647"
                        },
                    ],
                    "range": {
                        "min": "1",
                        "max": "2147483647"
                    },
                },
            },
            "access": "readonly",
            "default": "2147483647",
            "description":
                """This object identifies the specific notification issued by the
network element.""",
        },  # scalar
        "trapSequenceId": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.1.2",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Integer32",
                    "ranges": [
                        {
                            "min": "1",
                            "max": "2147483647"
                        },
                    ],
                    "range": {
                        "min": "1",
                        "max": "2147483647"
                    },
                },
            },
            "access": "readonly",
            "description":
                """This object identifies the specific notification issued by the
network element.""",
        },  # scalar
        "trapNetworkElemModelNumber": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.1.3",
            "status": "current",
            "syntax": {
                "type": {"module": "SNMPv2-TC", "name": "DisplayString"},
            },
            "access": "readonly",
            "description":
                """The value of this object is the model number of
the network element.  Combination of Model # and Serial # is used as the unique
identifier of the NE.""",
        },  # scalar
        "trapNetworkElemSerialNum": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.1.4",
            "status": "current",
            "syntax": {
                "type": {"module": "SNMPv2-TC", "name": "DisplayString"},
            },
            "access": "readonly",
            "description":
                """The value of this object is the serial number of
the network element. Combination of Model # and Serial # is used as the unique
identifier of the NE.""",
        },  # scalar
        "trapPerceivedSeverity": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.1.5",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Enumeration",
                    "cleared": {
                        "nodetype": "namednumber",
                        "number": "1"
                    },
                    "indeterminate": {
                        "nodetype": "namednumber",
                        "number": "2"
                    },
                    "warning": {
                        "nodetype": "namednumber",
                        "number": "3"
                    },
                    "minor": {
                        "nodetype": "namednumber",
                        "number": "4"
                    },
                    "major": {
                        "nodetype": "namednumber",
                        "number": "5"
                    },
                    "critical": {
                        "nodetype": "namednumber",
                        "number": "6"
                    },
                },
            },
            "access": "readonly",
            "description":
                """This parameter defines five severity levels, which provide 
an indication of how it is perceived that the capability 
of the managed object has been affected. The other level
is not a severity level, but indicates that an alarm has been
cleared, and thus is no longer in alarm state.  Note that this 
field has no meaning for configuration change traps.          """,
        },  # scalar
        "trapNetworkElemOperState": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.1.6",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Enumeration",
                    "enabled": {
                        "nodetype": "namednumber",
                        "number": "1"
                    },
                    "disabled": {
                        "nodetype": "namednumber",
                        "number": "2"
                    },
                },
            },
            "access": "readonly",
            "description":
                """The current Operational State of the Network Element
which generated the trap.""",
        },  # scalar
        "trapNetworkElemAlarmStatus": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.1.7",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Enumeration",
                    "idle": {
                        "nodetype": "namednumber",
                        "number": "1"
                    },
                    "indeterminate": {
                        "nodetype": "namednumber",
                        "number": "2"
                    },
                    "warning": {
                        "nodetype": "namednumber",
                        "number": "3"
                    },
                    "minor": {
                        "nodetype": "namednumber",
                        "number": "4"
                    },
                    "major": {
                        "nodetype": "namednumber",
                        "number": "5"
                    },
                    "critical": {
                        "nodetype": "namednumber",
                        "number": "6"
                    },
                },
            },
            "access": "readonly",
            "description":
                """The current Alarm Status of the Network Element
Alarm Status is always equal to the highest severity
level of all outstanding alarms in this NE.""",
        },  # scalar
        "trapNetworkElemAdminState": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.1.8",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Enumeration",
                    "locked": {
                        "nodetype": "namednumber",
                        "number": "1"
                    },
                    "unlocked": {
                        "nodetype": "namednumber",
                        "number": "2"
                    },
                    "shuttingDown": {
                        "nodetype": "namednumber",
                        "number": "3"
                    },
                },
            },
            "access": "readonly",
            "description":
                """The current Adminsitrative state of the network element.""",
        },  # scalar
        "trapNetworkElemAvailStatus": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.1.9",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Enumeration",
                    "inTest": {
                        "nodetype": "namednumber",
                        "number": "1"
                    },
                    "failed": {
                        "nodetype": "namednumber",
                        "number": "2"
                    },
                    "powerOff": {
                        "nodetype": "namednumber",
                        "number": "3"
                    },
                    "offLine": {
                        "nodetype": "namednumber",
                        "number": "4"
                    },
                    "offDuty": {
                        "nodetype": "namednumber",
                        "number": "5"
                    },
                    "dependency": {
                        "nodetype": "namednumber",
                        "number": "6"
                    },
                    "degraded": {
                        "nodetype": "namednumber",
                        "number": "7"
                    },
                    "notInstalled": {
                        "nodetype": "namednumber",
                        "number": "8"
                    },
                    "logFull": {
                        "nodetype": "namednumber",
                        "number": "9"
                    },
                    "available": {
                        "nodetype": "namednumber",
                        "number": "10"
                    },
                },
            },
            "access": "readonly",
            "description":
                """The current Operational state of the network elment
is defined in ISO/IEC 10164-2.""",
        },  # scalar
        "trapText": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.1.10",
            "status": "current",
            "syntax": {
                "type": {"module": "SNMPv2-TC", "name": "DisplayString"},
            },
            "access": "readonly",
            "description":
                """This  variable contains an optional trap text.""",
        },  # scalar
        "trapNETrapLastTrapTimeStamp": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.1.11",
            "status": "current",
            "syntax": {
                "type": {"module": "SNMPv2-SMI", "name": "TimeTicks"},
            },
            "access": "readonly",
            "description":
                """This OBJECT IDENTIFIER is used to hold time since NE was 'CHANGED'
last time.  'CHANGE' is defined as:
1) any write operation was performed on this NE which caused a trap.
2) any alarm was generated by this NE which caused a trap.
3) any alarm was cleared on this NE which caused a trap.""",
        },  # scalar
        "trapChangedObjectId": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.1.12",
            "status": "current",
            "syntax": {
                "type": {"module": "SNMPv2-TC", "name": "DisplayString"},
            },
            "access": "readonly",
            "description":
                """This  variable identifies the object that
has generated the trap.""",
        },  # scalar
        "trapAdditionalInfoInteger1": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.1.13",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Integer32",
                    "ranges": [
                        {
                            "min": "1",
                            "max": "2147483647"
                        },
                    ],
                    "range": {
                        "min": "1",
                        "max": "2147483647"
                    },
                },
            },
            "access": "readonly",
            "default": "2147483647",
            "description":
                """This 32 bit integer is used to hold specific information about 
the trap.""",
        },  # scalar
        "trapAdditionalInfoInteger2": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.1.14",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Integer32",
                    "ranges": [
                        {
                            "min": "1",
                            "max": "2147483647"
                        },
                    ],
                    "range": {
                        "min": "1",
                        "max": "2147483647"
                    },
                },
            },
            "access": "readonly",
            "default": "2147483647",
            "description":
                """This 32 bit integer is used to hold specific information about 
the trap.           """,
        },  # scalar
        "trapAdditionalInfoInteger3": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.1.15",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Integer32",
                    "ranges": [
                        {
                            "min": "1",
                            "max": "2147483647"
                        },
                    ],
                    "range": {
                        "min": "1",
                        "max": "2147483647"
                    },
                },
            },
            "access": "readonly",
            "default": "2147483647",
            "description":
                """This 32 bit integer is used to hold specific information about 
the trap.            """,
        },  # scalar
        "trapChangedValueDisplayString": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.1.16",
            "status": "current",
            "syntax": {
                "type": {"module": "SNMPv2-TC", "name": "DisplayString"},
            },
            "access": "readonly",
            "description":
                """This DisplayString is used to hold specific information about
the trap.""",
        },  # scalar
        "trapChangedValueOID": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.1.17",
            "status": "current",
            "syntax": {
                "type": {"module": "SNMPv2-TC", "name": "DisplayString"},
            },
            "access": "readonly",
            "description":
                """This OBJECT IDENTIFIER is used to hold specific information about 
the trap.""",
        },  # scalar
        "trapChangedValueIpAddress": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.1.18",
            "status": "current",
            "syntax": {
                "type": {"module": "SNMPv2-SMI", "name": "IpAddress"},
            },
            "access": "readonly",
            "description":
                """This OBJECT IDENTIFIER is used to hold specific information about 
the trap.""",
        },  # scalar
        "trapChangedValueInteger": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.1.19",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Integer32",
                    "ranges": [
                        {
                            "min": "1",
                            "max": "2147483647"
                        },
                    ],
                    "range": {
                        "min": "1",
                        "max": "2147483647"
                    },
                },
            },
            "access": "readonly",
            "default": "2147483647",
            "description":
                """This 32 bit integer is used to hold specific information about 
the trap.          """,
        },  # scalar
        "modSysTrapControl": {
            "nodetype": "node",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2",
        },  # node
        "numberOfTrapReceivers": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.1",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Integer32",
                    "ranges": [
                        {
                            "min": "1",
                            "max": "4"
                        },
                    ],
                    "range": {
                        "min": "1",
                        "max": "4"
                    },
                },
            },
            "access": "readonly",
            "description":
                """The number of managers to send traps to.
No longer needed but retained for compatibility.
No limit on number of recievers imposed by this MIB.""",
        },  # scalar
        "trapReceiversTable": {
            "nodetype": "table",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.2",
            "status": "current",
            "description":
                """A list of managers to send traps to.  The number of
entries is given by the value of NumTrapReceivers.
No limit on number of recievers imposed by this MIB.""",
        },  # table
        "trapReceiversEntry": {
            "nodetype": "row",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.2.1",
            "create": "true",
            "status": "current",
            "linkage": [
                "trapReceiversTableIndex",
            ],
            "description":
                """The list of managers to send traps.""",
        },  # row
        "trapReceiversTableIndex": {
            "nodetype": "column",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.2.1.1",
            "status": "current",
            "syntax": {
                "type": {"module": "", "name": "Integer32"},
            },
            "access": "noaccess",
            "description":
                """The index to a trap receiver entry.""",
        },  # column
        "trapReceiverAddr": {
            "nodetype": "column",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.2.1.2",
            "status": "current",
            "syntax": {
                "type": {"module": "SNMPv2-SMI", "name": "IpAddress"},
            },
            "access": "readwrite",
            "description":
                """The IP address of the manager to send a trap to.
NOTE: Changing TrapReceiverAddr FROM default value to
anything else is equivalent of 'creating' of a new entry.
Changing trapReceiverAddr TO default value will result
in deletion of that entry.""",
        },  # column
        "trapReceiverCommunityString": {
            "nodetype": "column",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.2.1.3",
            "status": "current",
            "syntax": {
                "type": {"module": "SNMPv2-TC", "name": "DisplayString"},
            },
            "access": "readwrite",
            "description":
                """The community name to use in the trap when
sent to the manager.""",
        },  # column
        "trapToBeSendQueueSize": {
            "nodetype": "column",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.2.1.4",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Integer32",
                    "ranges": [
                        {
                            "min": "50",
                            "max": "1000"
                        },
                    ],
                    "range": {
                        "min": "50",
                        "max": "1000"
                    },
                },
            },
            "access": "readwrite",
            "default": "50",
            "description":
                """The agent maintains 2 queues: TrapsToBeSendQueue and TrapsSentQueue.
The SNMP agent can receive a burst of traps which need to be sent
to the network manager.  The SNMP agent will put them in
TrapsToBeSendQueue and from there hi will send traps to the
a manager at throttling rate.  The traps will be kept in sequence
by the time at which they came in """,
        },  # column
        "trapSentQueueSize": {
            "nodetype": "column",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.2.1.5",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Integer32",
                    "ranges": [
                        {
                            "min": "50",
                            "max": "300"
                        },
                    ],
                    "range": {
                        "min": "50",
                        "max": "300"
                    },
                },
            },
            "access": "readwrite",
            "default": "50",
            "description":
                """The agent maintains 2 queues: TrapsToBeSendQueue and TrapsSentQueue.
The SNMP agent maintains Trap History (TrapsSentQueue) by saving last 'X'
sent traps.""",
        },  # column
        "trapThrottlingRate": {
            "nodetype": "column",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.2.1.6",
            "status": "current",
            "syntax": {
                "type": {"module": "", "name": "Integer32"},
            },
            "access": "readwrite",
            "default": "1",
            "description":
                """The number of traps agent can send to a particular manager
(trapReceiver) per second. """,
        },  # column
        "trapLastSent": {
            "nodetype": "column",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.2.1.7",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Integer32",
                    "ranges": [
                        {
                            "min": "1",
                            "max": "2147483647"
                        },
                    ],
                    "range": {
                        "min": "1",
                        "max": "2147483647"
                    },
                },
            },
            "access": "readonly",
            "default": "1",
            "description":
                """This variable contains the last trapSequenceId (sequence number) 
agent sent to this manager.  Upon startup agent will send
cold-start trap and set value of TrapLastSent to 1.""",
        },  # column
        "trapReceiversEntryOperState": {
            "nodetype": "column",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.2.1.8",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Enumeration",
                    "enabled": {
                        "nodetype": "namednumber",
                        "number": "1"
                    },
                    "disabled": {
                        "nodetype": "namednumber",
                        "number": "2"
                    },
                },
            },
            "access": "readwrite",
            "default": "disabled",
            "description":
                """The current Operational State of this entry
in trapReceivers Table """,
        },  # column
        "trapResendRequest": {
            "nodetype": "column",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.2.1.9",
            "status": "current",
            "syntax": {
                "type": {"module": "", "name": "Integer32"},
            },
            "access": "readwrite",
            "default": "2147483647",
            "description":
                """The manager may write this object when the indicated trap 
(indicated via trapIdentifier) should be resent.  It is not 
intended to be read by the manager, but is read-write for
compatability with older SNMP compilers.""",
        },  # column
        "trapReceiverEntryStatus": {
            "nodetype": "column",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.2.1.10",
            "status": "current",
            "syntax": {
                "type": {"module": "SNMPv2-TC", "name": "RowStatus"},
            },
            "access": "readwrite",
            "description":
                """Status of this entry.""",
        },  # column
        "numberOfDiscriminators": {
            "nodetype": "scalar",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.3",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Integer32",
                    "ranges": [
                        {
                            "min": "1",
                            "max": "2147483647"
                        },
                    ],
                    "range": {
                        "min": "1",
                        "max": "2147483647"
                    },
                },
            },
            "access": "readonly",
            "default": "2147483647",
            "description":
                """The number of EFDs (filters) agent has in it's database.
This number can not exceed 20 """,
        },  # scalar
        "trapDiscrimTable": {
            "nodetype": "table",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.4",
            "status": "current",
            "description":
                """A list of EFDs (trap filters).  Before forwarding trap to
a trapReceiver (manager) agent filters all traps acording
to all EFDs defined for this manager.""",
        },  # table
        "trapDiscrimEntry": {
            "nodetype": "row",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.4.1",
            "create": "true",
            "status": "current",
            "linkage": [
                "trapDiscrimTableIndex",
            ],
            "description":
                """The list of discriminators (trap filters.)""",
        },  # row
        "trapDiscrimTableIndex": {
            "nodetype": "column",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.4.1.1",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Integer32",
                    "ranges": [
                        {
                            "min": "1",
                            "max": "20"
                        },
                    ],
                    "range": {
                        "min": "1",
                        "max": "20"
                    },
                },
            },
            "access": "noaccess",
            "description":
                """The index to a trap discriminator entry.""",
        },  # column
        "trapDiscrimReceiverAddr": {
            "nodetype": "column",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.4.1.2",
            "status": "current",
            "syntax": {
                "type": {"module": "SNMPv2-SMI", "name": "IpAddress"},
            },
            "access": "readwrite",
            "description":
                """The IP address of the manager this Discrim belongs to.
It should be equal to TrapReceiverAddr.
NOTE: Changing trapDiscrimReceiverAddr FROM default value to
anything else is equivalent of 'creating' of a new entry.
Changing trapReceiverAddr TO default value will result
in deletion of that entry.""",
        },  # column
        "trapDiscrimAvailabilityStatus": {
            "nodetype": "column",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.4.1.3",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Enumeration",
                    "offDuty": {
                        "nodetype": "namednumber",
                        "number": "5"
                    },
                    "available": {
                        "nodetype": "namednumber",
                        "number": "10"
                    },
                },
            },
            "access": "readonly",
            "description":
                """This object reflects the current Availability status of the
Discrim (based on ISO/IEC 10164-2).""",
        },  # column
        "trapDiscrimWeeklyMask": {
            "nodetype": "column",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.4.1.4",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "OctetString",
                    "parent module": {
                        "name": "SNMPv2-TC",
                        "type": "DisplayString",
                    },
                    "ranges": [
                        {
                            "min": "0",
                            "max": "6"
                        },
                    ],
                    "range": {
                        "min": "0",
                        "max": "6"
                    },
                },
            },
            "access": "readwrite",
            "description":
                """This object represents weekly scedule for corresponding
Discrim.  The WeeklyMask consists of 7 numeric 
characters (1 for each day of the week).  Each numeric
character can take a value of eather '1' - enabled or 
'2' - disabled.  For example, with WeeklyMask='1122221',
an agent will aplly corresponding Disriminator only on
Mondays, Tuesdays and Sundays.
Any characters other than '1' and '2' will be ignored.""",
        },  # column
        "trapDiscrimDailyStartTime": {
            "nodetype": "column",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.4.1.5",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Integer32",
                    "ranges": [
                        {
                            "min": "0",
                            "max": "1439"
                        },
                    ],
                    "range": {
                        "min": "0",
                        "max": "1439"
                    },
                },
            },
            "access": "readwrite",
            "description":
                """This object represents daily start time for corresponding
Discrim.  The StartTime is expressed as an offset
(in minutes) from 2400 hours military time.  For example,
StartTime=70 represents start time of 1:10 AM.""",
        },  # column
        "trapDiscrimDailyStopTime": {
            "nodetype": "column",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.4.1.6",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Integer32",
                    "ranges": [
                        {
                            "min": "0",
                            "max": "1439"
                        },
                    ],
                    "range": {
                        "min": "0",
                        "max": "1439"
                    },
                },
            },
            "access": "readwrite",
            "description":
                """This object represents daily stop time for corresponding
Discrim.  The StopTime is expressed as an offset
(in minutes) from 2400 hours military time.  For example,
StopTime=70 represents stop time of 1:10 AM.""",
        },  # column
        "trapSeverityDiscrim": {
            "nodetype": "column",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.4.1.7",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Enumeration",
                    "indeterminate": {
                        "nodetype": "namednumber",
                        "number": "2"
                    },
                    "warning": {
                        "nodetype": "namednumber",
                        "number": "3"
                    },
                    "minor": {
                        "nodetype": "namednumber",
                        "number": "4"
                    },
                    "major": {
                        "nodetype": "namednumber",
                        "number": "5"
                    },
                    "critical": {
                        "nodetype": "namednumber",
                        "number": "6"
                    },
                },
            },
            "access": "readwrite",
            "description":
                """The severity threshold of traps to be send to the manager.
Only traps of equal or greater severity than
this value are sent to the manager.""",
        },  # column
        "trapDiscrimOperationalState": {
            "nodetype": "column",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.4.1.8",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Enumeration",
                    "enabled": {
                        "nodetype": "namednumber",
                        "number": "1"
                    },
                    "disabled": {
                        "nodetype": "namednumber",
                        "number": "2"
                    },
                },
            },
            "access": "readwrite",
            "default": "disabled",
            "description":
                """The current Operational State of the Discriminator. """,
        },  # column
        "trapDiscrimConfigChangeCntl": {
            "nodetype": "column",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.4.1.9",
            "status": "current",
            "syntax": {
                "type":                 {
                    "basetype": "Enumeration",
                    "on": {
                        "nodetype": "namednumber",
                        "number": "1"
                    },
                    "off": {
                        "nodetype": "namednumber",
                        "number": "2"
                    },
                },
            },
            "access": "readwrite",
            "default": "on",
            "description":
                """This variable turns reporting of configuration changes 
on or off. """,
        },  # column
        "trapDiscrimEntryStatus": {
            "nodetype": "column",
            "moduleName": "MOD-SYS-TRAPS-MIB",
            "oid": "0.3.2.4.1.10",
            "status": "current",
            "syntax": {
                "type": {"module": "SNMPv2-TC", "name": "RowStatus"},
            },
            "access": "readwrite",
            "description":
                """Status of this entry.""",
        },  # column
    },  # nodes

}
